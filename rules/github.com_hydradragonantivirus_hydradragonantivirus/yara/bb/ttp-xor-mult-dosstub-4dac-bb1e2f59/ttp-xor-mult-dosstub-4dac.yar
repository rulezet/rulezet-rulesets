rule TTP_XOR_MULT_DOSStub_4dac {
  strings:
    $key_4dac = { 19 c4 [2] 6d dc [2] 2a de [2] 6d cf [2] 23 c3 [2] 2f c9 [2] 38 c2 [2] 23 8c [2] 1e }

  condition:
    any of them
}