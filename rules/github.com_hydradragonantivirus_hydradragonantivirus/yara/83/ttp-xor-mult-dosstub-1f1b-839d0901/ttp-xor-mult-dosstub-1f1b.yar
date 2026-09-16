rule TTP_XOR_MULT_DOSStub_1f1b {
  strings:
    $key_1f1b = { 4b 73 [2] 3f 6b [2] 78 69 [2] 3f 78 [2] 71 74 [2] 7d 7e [2] 6a 75 [2] 71 3b [2] 4c }

  condition:
    any of them
}