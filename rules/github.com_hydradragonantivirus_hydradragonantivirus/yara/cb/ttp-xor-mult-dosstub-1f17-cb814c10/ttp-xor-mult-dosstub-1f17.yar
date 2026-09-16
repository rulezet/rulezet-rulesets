rule TTP_XOR_MULT_DOSStub_1f17 {
  strings:
    $key_1f17 = { 4b 7f [2] 3f 67 [2] 78 65 [2] 3f 74 [2] 71 78 [2] 7d 72 [2] 6a 79 [2] 71 37 [2] 4c }

  condition:
    any of them
}