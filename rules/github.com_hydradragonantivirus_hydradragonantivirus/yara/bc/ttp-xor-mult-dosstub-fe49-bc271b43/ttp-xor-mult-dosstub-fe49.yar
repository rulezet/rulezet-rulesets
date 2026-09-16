rule TTP_XOR_MULT_DOSStub_fe49 {
  strings:
    $key_fe49 = { aa 21 [2] de 39 [2] 99 3b [2] de 2a [2] 90 26 [2] 9c 2c [2] 8b 27 [2] 90 69 [2] ad }

  condition:
    any of them
}