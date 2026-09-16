rule TTP_XOR_MULT_DOSStub_4403 {
  strings:
    $key_4403 = { 10 6b [2] 64 73 [2] 23 71 [2] 64 60 [2] 2a 6c [2] 26 66 [2] 31 6d [2] 2a 23 [2] 17 }

  condition:
    any of them
}