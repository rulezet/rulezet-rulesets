rule TTP_XOR_MULT_DOSStub_1f08 {
  strings:
    $key_1f08 = { 4b 60 [2] 3f 78 [2] 78 7a [2] 3f 6b [2] 71 67 [2] 7d 6d [2] 6a 66 [2] 71 28 [2] 4c }

  condition:
    any of them
}