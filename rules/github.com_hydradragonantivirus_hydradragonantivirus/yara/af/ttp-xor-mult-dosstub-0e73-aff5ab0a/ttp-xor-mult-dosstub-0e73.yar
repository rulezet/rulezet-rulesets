rule TTP_XOR_MULT_DOSStub_0e73 {
  strings:
    $key_0e73 = { 5a 1b [2] 2e 03 [2] 69 01 [2] 2e 10 [2] 60 1c [2] 6c 16 [2] 7b 1d [2] 60 53 [2] 5d }

  condition:
    any of them
}