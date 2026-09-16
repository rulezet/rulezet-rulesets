rule TTP_XOR_MULT_DOSStub_4f03 {
  strings:
    $key_4f03 = { 1b 6b [2] 6f 73 [2] 28 71 [2] 6f 60 [2] 21 6c [2] 2d 66 [2] 3a 6d [2] 21 23 [2] 1c }

  condition:
    any of them
}