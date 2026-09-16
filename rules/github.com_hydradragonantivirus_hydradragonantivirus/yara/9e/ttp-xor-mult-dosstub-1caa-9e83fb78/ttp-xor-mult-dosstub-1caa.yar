rule TTP_XOR_MULT_DOSStub_1caa {
  strings:
    $key_1caa = { 48 c2 [2] 3c da [2] 7b d8 [2] 3c c9 [2] 72 c5 [2] 7e cf [2] 69 c4 [2] 72 8a [2] 4f }

  condition:
    any of them
}