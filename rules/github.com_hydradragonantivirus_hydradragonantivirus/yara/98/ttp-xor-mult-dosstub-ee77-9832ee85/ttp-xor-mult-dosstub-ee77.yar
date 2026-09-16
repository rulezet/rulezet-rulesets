rule TTP_XOR_MULT_DOSStub_ee77 {
  strings:
    $key_ee77 = { ba 1f [2] ce 07 [2] 89 05 [2] ce 14 [2] 80 18 [2] 8c 12 [2] 9b 19 [2] 80 57 [2] bd }

  condition:
    any of them
}