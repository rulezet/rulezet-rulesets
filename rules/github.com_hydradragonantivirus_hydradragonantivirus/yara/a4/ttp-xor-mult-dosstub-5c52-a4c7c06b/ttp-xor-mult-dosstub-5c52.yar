rule TTP_XOR_MULT_DOSStub_5c52 {
  strings:
    $key_5c52 = { 08 3a [2] 7c 22 [2] 3b 20 [2] 7c 31 [2] 32 3d [2] 3e 37 [2] 29 3c [2] 32 72 [2] 0f }

  condition:
    any of them
}