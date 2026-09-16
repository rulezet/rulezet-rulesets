rule TTP_XOR_MULT_DOSStub_3c3d {
  strings:
    $key_3c3d = { 68 55 [2] 1c 4d [2] 5b 4f [2] 1c 5e [2] 52 52 [2] 5e 58 [2] 49 53 [2] 52 1d [2] 6f }

  condition:
    any of them
}