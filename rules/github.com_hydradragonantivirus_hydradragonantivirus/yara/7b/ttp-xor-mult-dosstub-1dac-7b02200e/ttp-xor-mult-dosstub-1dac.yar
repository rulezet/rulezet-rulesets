rule TTP_XOR_MULT_DOSStub_1dac {
  strings:
    $key_1dac = { 49 c4 [2] 3d dc [2] 7a de [2] 3d cf [2] 73 c3 [2] 7f c9 [2] 68 c2 [2] 73 8c [2] 4e }

  condition:
    any of them
}