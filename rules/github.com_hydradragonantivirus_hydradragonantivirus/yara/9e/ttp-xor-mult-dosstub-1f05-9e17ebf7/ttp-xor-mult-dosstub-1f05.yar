rule TTP_XOR_MULT_DOSStub_1f05 {
  strings:
    $key_1f05 = { 4b 6d [2] 3f 75 [2] 78 77 [2] 3f 66 [2] 71 6a [2] 7d 60 [2] 6a 6b [2] 71 25 [2] 4c }

  condition:
    any of them
}