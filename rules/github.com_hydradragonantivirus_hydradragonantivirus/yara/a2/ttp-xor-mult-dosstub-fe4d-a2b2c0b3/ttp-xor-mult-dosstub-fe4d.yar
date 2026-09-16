rule TTP_XOR_MULT_DOSStub_fe4d {
  strings:
    $key_fe4d = { aa 25 [2] de 3d [2] 99 3f [2] de 2e [2] 90 22 [2] 9c 28 [2] 8b 23 [2] 90 6d [2] ad }

  condition:
    any of them
}