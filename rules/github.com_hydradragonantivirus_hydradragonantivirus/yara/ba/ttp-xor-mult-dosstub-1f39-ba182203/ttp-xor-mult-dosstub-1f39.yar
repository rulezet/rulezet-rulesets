rule TTP_XOR_MULT_DOSStub_1f39 {
  strings:
    $key_1f39 = { 4b 51 [2] 3f 49 [2] 78 4b [2] 3f 5a [2] 71 56 [2] 7d 5c [2] 6a 57 [2] 71 19 [2] 4c }

  condition:
    any of them
}