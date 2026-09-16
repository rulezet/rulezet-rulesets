rule TTP_XOR_MULT_DOSStub_5c4d {
  strings:
    $key_5c4d = { 08 25 [2] 7c 3d [2] 3b 3f [2] 7c 2e [2] 32 22 [2] 3e 28 [2] 29 23 [2] 32 6d [2] 0f }

  condition:
    any of them
}