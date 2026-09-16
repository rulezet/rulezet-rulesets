rule TTP_XOR_MULT_DOSStub_6dac {
  strings:
    $key_6dac = { 39 c4 [2] 4d dc [2] 0a de [2] 4d cf [2] 03 c3 [2] 0f c9 [2] 18 c2 [2] 03 8c [2] 3e }

  condition:
    any of them
}