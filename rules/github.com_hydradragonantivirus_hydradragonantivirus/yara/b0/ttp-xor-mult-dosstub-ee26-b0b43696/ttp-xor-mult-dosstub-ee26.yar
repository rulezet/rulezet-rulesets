rule TTP_XOR_MULT_DOSStub_ee26 {
  strings:
    $key_ee26 = { ba 4e [2] ce 56 [2] 89 54 [2] ce 45 [2] 80 49 [2] 8c 43 [2] 9b 48 [2] 80 06 [2] bd }

  condition:
    any of them
}