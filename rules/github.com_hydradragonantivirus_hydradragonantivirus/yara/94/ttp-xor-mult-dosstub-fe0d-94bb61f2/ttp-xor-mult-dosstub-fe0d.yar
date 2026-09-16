rule TTP_XOR_MULT_DOSStub_fe0d {
  strings:
    $key_fe0d = { aa 65 [2] de 7d [2] 99 7f [2] de 6e [2] 90 62 [2] 9c 68 [2] 8b 63 [2] 90 2d [2] ad }

  condition:
    any of them
}