rule TTP_XOR_MULT_DOSStub_fe66 {
  strings:
    $key_fe66 = { aa 0e [2] de 16 [2] 99 14 [2] de 05 [2] 90 09 [2] 9c 03 [2] 8b 08 [2] 90 46 [2] ad }

  condition:
    any of them
}