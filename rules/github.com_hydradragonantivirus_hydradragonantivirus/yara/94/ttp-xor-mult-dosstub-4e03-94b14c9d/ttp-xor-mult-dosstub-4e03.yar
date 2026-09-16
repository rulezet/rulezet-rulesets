rule TTP_XOR_MULT_DOSStub_4e03 {
  strings:
    $key_4e03 = { 1a 6b [2] 6e 73 [2] 29 71 [2] 6e 60 [2] 20 6c [2] 2c 66 [2] 3b 6d [2] 20 23 [2] 1d }

  condition:
    any of them
}