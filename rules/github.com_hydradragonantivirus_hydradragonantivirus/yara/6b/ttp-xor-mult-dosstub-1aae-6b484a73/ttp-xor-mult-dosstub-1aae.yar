rule TTP_XOR_MULT_DOSStub_1aae {
  strings:
    $key_1aae = { 4e c6 [2] 3a de [2] 7d dc [2] 3a cd [2] 74 c1 [2] 78 cb [2] 6f c0 [2] 74 8e [2] 49 }

  condition:
    any of them
}