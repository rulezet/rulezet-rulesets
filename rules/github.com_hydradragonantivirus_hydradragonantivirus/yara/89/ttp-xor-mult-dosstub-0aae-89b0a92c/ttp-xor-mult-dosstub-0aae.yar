rule TTP_XOR_MULT_DOSStub_0aae {
  strings:
    $key_0aae = { 5e c6 [2] 2a de [2] 6d dc [2] 2a cd [2] 64 c1 [2] 68 cb [2] 7f c0 [2] 64 8e [2] 59 }

  condition:
    any of them
}