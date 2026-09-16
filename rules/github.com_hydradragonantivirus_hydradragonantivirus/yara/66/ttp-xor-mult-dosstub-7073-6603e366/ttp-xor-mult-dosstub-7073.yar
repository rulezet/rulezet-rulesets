rule TTP_XOR_MULT_DOSStub_7073 {
  strings:
    $key_7073 = { 24 1b [2] 50 03 [2] 17 01 [2] 50 10 [2] 1e 1c [2] 12 16 [2] 05 1d [2] 1e 53 [2] 23 }

  condition:
    any of them
}