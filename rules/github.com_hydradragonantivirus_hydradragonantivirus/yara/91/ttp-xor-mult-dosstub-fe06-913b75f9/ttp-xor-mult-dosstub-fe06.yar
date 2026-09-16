rule TTP_XOR_MULT_DOSStub_fe06 {
  strings:
    $key_fe06 = { aa 6e [2] de 76 [2] 99 74 [2] de 65 [2] 90 69 [2] 9c 63 [2] 8b 68 [2] 90 26 [2] ad }

  condition:
    any of them
}