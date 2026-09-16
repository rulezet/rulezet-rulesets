rule TTP_XOR_MULT_DOSStub_5caa {
  strings:
    $key_5caa = { 08 c2 [2] 7c da [2] 3b d8 [2] 7c c9 [2] 32 c5 [2] 3e cf [2] 29 c4 [2] 32 8a [2] 0f }

  condition:
    any of them
}