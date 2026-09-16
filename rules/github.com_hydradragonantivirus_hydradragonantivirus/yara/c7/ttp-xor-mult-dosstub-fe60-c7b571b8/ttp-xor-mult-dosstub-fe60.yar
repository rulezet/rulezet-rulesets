rule TTP_XOR_MULT_DOSStub_fe60 {
  strings:
    $key_fe60 = { aa 08 [2] de 10 [2] 99 12 [2] de 03 [2] 90 0f [2] 9c 05 [2] 8b 0e [2] 90 40 [2] ad }

  condition:
    any of them
}