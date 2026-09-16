rule TTP_XOR_MULT_DOSStub_5c3d {
  strings:
    $key_5c3d = { 08 55 [2] 7c 4d [2] 3b 4f [2] 7c 5e [2] 32 52 [2] 3e 58 [2] 29 53 [2] 32 1d [2] 0f }

  condition:
    any of them
}