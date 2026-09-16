rule TTP_XOR_MULT_DOSStub_fe65 {
  strings:
    $key_fe65 = { aa 0d [2] de 15 [2] 99 17 [2] de 06 [2] 90 0a [2] 9c 00 [2] 8b 0b [2] 90 45 [2] ad }

  condition:
    any of them
}