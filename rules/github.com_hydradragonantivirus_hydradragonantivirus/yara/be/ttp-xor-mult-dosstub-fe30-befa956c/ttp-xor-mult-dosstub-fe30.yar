rule TTP_XOR_MULT_DOSStub_fe30 {
  strings:
    $key_fe30 = { aa 58 [2] de 40 [2] 99 42 [2] de 53 [2] 90 5f [2] 9c 55 [2] 8b 5e [2] 90 10 [2] ad }

  condition:
    any of them
}