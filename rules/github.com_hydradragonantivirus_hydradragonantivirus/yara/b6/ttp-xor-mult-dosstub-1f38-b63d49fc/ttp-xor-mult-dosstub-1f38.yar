rule TTP_XOR_MULT_DOSStub_1f38 {
  strings:
    $key_1f38 = { 4b 50 [2] 3f 48 [2] 78 4a [2] 3f 5b [2] 71 57 [2] 7d 5d [2] 6a 56 [2] 71 18 [2] 4c }

  condition:
    any of them
}