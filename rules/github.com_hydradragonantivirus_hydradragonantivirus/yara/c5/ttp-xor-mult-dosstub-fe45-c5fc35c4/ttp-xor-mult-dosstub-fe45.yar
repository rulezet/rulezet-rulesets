rule TTP_XOR_MULT_DOSStub_fe45 {
  strings:
    $key_fe45 = { aa 2d [2] de 35 [2] 99 37 [2] de 26 [2] 90 2a [2] 9c 20 [2] 8b 2b [2] 90 65 [2] ad }

  condition:
    any of them
}