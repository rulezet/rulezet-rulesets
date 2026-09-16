rule TTP_XOR_MULT_DOSStub_fe63 {
  strings:
    $key_fe63 = { aa 0b [2] de 13 [2] 99 11 [2] de 00 [2] 90 0c [2] 9c 06 [2] 8b 0d [2] 90 43 [2] ad }

  condition:
    any of them
}