rule TTP_XOR_MULT_DOSStub_5aae {
  strings:
    $key_5aae = { 0e c6 [2] 7a de [2] 3d dc [2] 7a cd [2] 34 c1 [2] 38 cb [2] 2f c0 [2] 34 8e [2] 09 }

  condition:
    any of them
}