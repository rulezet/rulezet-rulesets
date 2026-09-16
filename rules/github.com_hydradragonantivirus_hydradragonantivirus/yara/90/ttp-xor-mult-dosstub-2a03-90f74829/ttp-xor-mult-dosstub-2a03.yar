rule TTP_XOR_MULT_DOSStub_2a03 {
  strings:
    $key_2a03 = { 7e 6b [2] 0a 73 [2] 4d 71 [2] 0a 60 [2] 44 6c [2] 48 66 [2] 5f 6d [2] 44 23 [2] 79 }

  condition:
    any of them
}