rule TTP_XOR_MULT_DOSStub_fe5d {
  strings:
    $key_fe5d = { aa 35 [2] de 2d [2] 99 2f [2] de 3e [2] 90 32 [2] 9c 38 [2] 8b 33 [2] 90 7d [2] ad }

  condition:
    any of them
}