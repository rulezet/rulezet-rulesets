rule TTP_XOR_MULT_DOSStub_fe42 {
  strings:
    $key_fe42 = { aa 2a [2] de 32 [2] 99 30 [2] de 21 [2] 90 2d [2] 9c 27 [2] 8b 2c [2] 90 62 [2] ad }

  condition:
    any of them
}