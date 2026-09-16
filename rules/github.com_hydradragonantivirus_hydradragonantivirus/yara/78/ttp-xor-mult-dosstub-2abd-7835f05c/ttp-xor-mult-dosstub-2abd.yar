rule TTP_XOR_MULT_DOSStub_2abd {
  strings:
    $key_2abd = { 7e d5 [2] 0a cd [2] 4d cf [2] 0a de [2] 44 d2 [2] 48 d8 [2] 5f d3 [2] 44 9d [2] 79 }

  condition:
    any of them
}