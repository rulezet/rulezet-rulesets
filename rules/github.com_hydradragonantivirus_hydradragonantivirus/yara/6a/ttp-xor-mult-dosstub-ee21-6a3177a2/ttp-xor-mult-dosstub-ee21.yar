rule TTP_XOR_MULT_DOSStub_ee21 {
  strings:
    $key_ee21 = { ba 49 [2] ce 51 [2] 89 53 [2] ce 42 [2] 80 4e [2] 8c 44 [2] 9b 4f [2] 80 01 [2] bd }

  condition:
    any of them
}