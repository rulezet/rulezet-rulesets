rule TTP_XOR_MULT_DOSStub_0a03 {
  strings:
    $key_0a03 = { 5e 6b [2] 2a 73 [2] 6d 71 [2] 2a 60 [2] 64 6c [2] 68 66 [2] 7f 6d [2] 64 23 [2] 59 }

  condition:
    any of them
}