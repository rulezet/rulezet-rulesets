rule TTP_XOR_MULT_DOSStub_fe52 {
  strings:
    $key_fe52 = { aa 3a [2] de 22 [2] 99 20 [2] de 31 [2] 90 3d [2] 9c 37 [2] 8b 3c [2] 90 72 [2] ad }

  condition:
    any of them
}