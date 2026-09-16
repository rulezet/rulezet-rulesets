rule TTP_XOR_MULT_DOSStub_0d03 {
  strings:
    $key_0d03 = { 59 6b [2] 2d 73 [2] 6a 71 [2] 2d 60 [2] 63 6c [2] 6f 66 [2] 78 6d [2] 63 23 [2] 5e }

  condition:
    any of them
}