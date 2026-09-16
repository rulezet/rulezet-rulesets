rule TTP_XOR_MULT_DOSStub_fe41 {
  strings:
    $key_fe41 = { aa 29 [2] de 31 [2] 99 33 [2] de 22 [2] 90 2e [2] 9c 24 [2] 8b 2f [2] 90 61 [2] ad }

  condition:
    any of them
}