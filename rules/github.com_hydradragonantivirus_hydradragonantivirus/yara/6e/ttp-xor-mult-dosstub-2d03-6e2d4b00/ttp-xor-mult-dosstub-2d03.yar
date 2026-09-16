rule TTP_XOR_MULT_DOSStub_2d03 {
  strings:
    $key_2d03 = { 79 6b [2] 0d 73 [2] 4a 71 [2] 0d 60 [2] 43 6c [2] 4f 66 [2] 58 6d [2] 43 23 [2] 7e }

  condition:
    any of them
}