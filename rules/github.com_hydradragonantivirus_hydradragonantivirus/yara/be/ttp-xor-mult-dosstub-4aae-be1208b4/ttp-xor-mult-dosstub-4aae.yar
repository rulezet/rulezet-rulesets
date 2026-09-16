rule TTP_XOR_MULT_DOSStub_4aae {
  strings:
    $key_4aae = { 1e c6 [2] 6a de [2] 2d dc [2] 6a cd [2] 24 c1 [2] 28 cb [2] 3f c0 [2] 24 8e [2] 19 }

  condition:
    any of them
}