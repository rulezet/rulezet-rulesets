rule TTP_XOR_MULT_DOSStub_1f09 {
  strings:
    $key_1f09 = { 4b 61 [2] 3f 79 [2] 78 7b [2] 3f 6a [2] 71 66 [2] 7d 6c [2] 6a 67 [2] 71 29 [2] 4c }

  condition:
    any of them
}