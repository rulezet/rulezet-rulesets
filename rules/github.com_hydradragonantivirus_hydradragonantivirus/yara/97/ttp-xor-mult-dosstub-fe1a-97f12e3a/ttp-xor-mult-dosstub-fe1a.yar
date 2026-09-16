rule TTP_XOR_MULT_DOSStub_fe1a {
  strings:
    $key_fe1a = { aa 72 [2] de 6a [2] 99 68 [2] de 79 [2] 90 75 [2] 9c 7f [2] 8b 74 [2] 90 3a [2] ad }

  condition:
    any of them
}