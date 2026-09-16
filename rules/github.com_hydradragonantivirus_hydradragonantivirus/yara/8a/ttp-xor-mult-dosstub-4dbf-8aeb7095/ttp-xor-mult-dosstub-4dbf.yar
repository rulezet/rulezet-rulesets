rule TTP_XOR_MULT_DOSStub_4dbf {
  strings:
    $key_4dbf = { 19 d7 [2] 6d cf [2] 2a cd [2] 6d dc [2] 23 d0 [2] 2f da [2] 38 d1 [2] 23 9f [2] 1e }

  condition:
    any of them
}