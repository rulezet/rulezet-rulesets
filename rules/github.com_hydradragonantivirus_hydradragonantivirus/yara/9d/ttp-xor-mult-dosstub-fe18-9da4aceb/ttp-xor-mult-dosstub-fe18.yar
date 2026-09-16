rule TTP_XOR_MULT_DOSStub_fe18 {
  strings:
    $key_fe18 = { aa 70 [2] de 68 [2] 99 6a [2] de 7b [2] 90 77 [2] 9c 7d [2] 8b 76 [2] 90 38 [2] ad }

  condition:
    any of them
}