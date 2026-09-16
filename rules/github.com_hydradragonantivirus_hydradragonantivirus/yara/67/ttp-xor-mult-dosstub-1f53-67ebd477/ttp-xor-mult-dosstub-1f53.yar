rule TTP_XOR_MULT_DOSStub_1f53 {
  strings:
    $key_1f53 = { 4b 3b [2] 3f 23 [2] 78 21 [2] 3f 30 [2] 71 3c [2] 7d 36 [2] 6a 3d [2] 71 73 [2] 4c }

  condition:
    any of them
}