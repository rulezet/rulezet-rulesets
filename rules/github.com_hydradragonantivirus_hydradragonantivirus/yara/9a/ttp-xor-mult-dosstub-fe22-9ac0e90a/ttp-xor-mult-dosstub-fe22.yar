rule TTP_XOR_MULT_DOSStub_fe22 {
  strings:
    $key_fe22 = { aa 4a [2] de 52 [2] 99 50 [2] de 41 [2] 90 4d [2] 9c 47 [2] 8b 4c [2] 90 02 [2] ad }

  condition:
    any of them
}