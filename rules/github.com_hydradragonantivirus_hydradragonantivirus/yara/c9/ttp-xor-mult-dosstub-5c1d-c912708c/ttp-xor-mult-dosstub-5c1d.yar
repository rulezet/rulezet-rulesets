rule TTP_XOR_MULT_DOSStub_5c1d {
  strings:
    $key_5c1d = { 08 75 [2] 7c 6d [2] 3b 6f [2] 7c 7e [2] 32 72 [2] 3e 78 [2] 29 73 [2] 32 3d [2] 0f }

  condition:
    any of them
}