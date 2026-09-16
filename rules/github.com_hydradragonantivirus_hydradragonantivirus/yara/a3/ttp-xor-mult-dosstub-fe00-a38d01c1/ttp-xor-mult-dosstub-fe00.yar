rule TTP_XOR_MULT_DOSStub_fe00 {
  strings:
    $key_fe00 = { aa 68 [2] de 70 [2] 99 72 [2] de 63 [2] 90 6f [2] 9c 65 [2] 8b 6e [2] 90 20 [2] ad }

  condition:
    any of them
}