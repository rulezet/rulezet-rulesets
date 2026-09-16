rule TTP_XOR_MULT_DOSStub_4073 {
  strings:
    $key_4073 = { 14 1b [2] 60 03 [2] 27 01 [2] 60 10 [2] 2e 1c [2] 22 16 [2] 35 1d [2] 2e 53 [2] 13 }

  condition:
    any of them
}