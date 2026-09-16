rule TTP_XOR_MULT_DOSStub_fe68 {
  strings:
    $key_fe68 = { aa 00 [2] de 18 [2] 99 1a [2] de 0b [2] 90 07 [2] 9c 0d [2] 8b 06 [2] 90 48 [2] ad }

  condition:
    any of them
}