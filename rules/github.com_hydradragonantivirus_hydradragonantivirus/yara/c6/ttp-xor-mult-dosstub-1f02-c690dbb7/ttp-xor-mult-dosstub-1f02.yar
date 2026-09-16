rule TTP_XOR_MULT_DOSStub_1f02 {
  strings:
    $key_1f02 = { 4b 6a [2] 3f 72 [2] 78 70 [2] 3f 61 [2] 71 6d [2] 7d 67 [2] 6a 6c [2] 71 22 [2] 4c }

  condition:
    any of them
}