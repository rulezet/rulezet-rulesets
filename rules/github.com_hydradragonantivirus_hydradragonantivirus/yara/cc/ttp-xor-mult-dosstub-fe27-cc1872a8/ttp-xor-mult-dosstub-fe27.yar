rule TTP_XOR_MULT_DOSStub_fe27 {
  strings:
    $key_fe27 = { aa 4f [2] de 57 [2] 99 55 [2] de 44 [2] 90 48 [2] 9c 42 [2] 8b 49 [2] 90 07 [2] ad }

  condition:
    any of them
}