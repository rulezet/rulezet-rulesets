rule TTP_XOR_MULT_DOSStub_fe3d {
  strings:
    $key_fe3d = { aa 55 [2] de 4d [2] 99 4f [2] de 5e [2] 90 52 [2] 9c 58 [2] 8b 53 [2] 90 1d [2] ad }

  condition:
    any of them
}