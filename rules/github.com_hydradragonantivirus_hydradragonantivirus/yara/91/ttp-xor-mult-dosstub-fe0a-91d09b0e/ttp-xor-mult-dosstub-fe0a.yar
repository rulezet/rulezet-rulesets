rule TTP_XOR_MULT_DOSStub_fe0a {
  strings:
    $key_fe0a = { aa 62 [2] de 7a [2] 99 78 [2] de 69 [2] 90 65 [2] 9c 6f [2] 8b 64 [2] 90 2a [2] ad }

  condition:
    any of them
}