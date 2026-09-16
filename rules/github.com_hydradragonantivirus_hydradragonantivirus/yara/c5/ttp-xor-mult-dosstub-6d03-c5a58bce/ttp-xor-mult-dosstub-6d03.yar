rule TTP_XOR_MULT_DOSStub_6d03 {
  strings:
    $key_6d03 = { 39 6b [2] 4d 73 [2] 0a 71 [2] 4d 60 [2] 03 6c [2] 0f 66 [2] 18 6d [2] 03 23 [2] 3e }

  condition:
    any of them
}