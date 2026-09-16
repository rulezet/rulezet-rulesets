rule TTP_XOR_MULT_DOSStub_6403 {
  strings:
    $key_6403 = { 30 6b [2] 44 73 [2] 03 71 [2] 44 60 [2] 0a 6c [2] 06 66 [2] 11 6d [2] 0a 23 [2] 37 }

  condition:
    any of them
}