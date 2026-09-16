rule TTP_XOR_MULT_DOSStub_2dac {
  strings:
    $key_2dac = { 79 c4 [2] 0d dc [2] 4a de [2] 0d cf [2] 43 c3 [2] 4f c9 [2] 58 c2 [2] 43 8c [2] 7e }

  condition:
    any of them
}