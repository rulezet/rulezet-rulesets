rule TTP_XOR_MULT_DOSStub_fe79 {
  strings:
    $key_fe79 = { aa 11 [2] de 09 [2] 99 0b [2] de 1a [2] 90 16 [2] 9c 1c [2] 8b 17 [2] 90 59 [2] ad }

  condition:
    any of them
}