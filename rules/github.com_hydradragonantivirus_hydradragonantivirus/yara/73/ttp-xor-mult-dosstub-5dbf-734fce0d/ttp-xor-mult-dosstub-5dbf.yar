rule TTP_XOR_MULT_DOSStub_5dbf {
  strings:
    $key_5dbf = { 09 d7 [2] 7d cf [2] 3a cd [2] 7d dc [2] 33 d0 [2] 3f da [2] 28 d1 [2] 33 9f [2] 0e }

  condition:
    any of them
}