rule TTP_XOR_MULT_DOSStub_4f53 {
  strings:
    $key_4f53 = { 1b 3b [2] 6f 23 [2] 28 21 [2] 6f 30 [2] 21 3c [2] 2d 36 [2] 3a 3d [2] 21 73 [2] 1c }

  condition:
    any of them
}