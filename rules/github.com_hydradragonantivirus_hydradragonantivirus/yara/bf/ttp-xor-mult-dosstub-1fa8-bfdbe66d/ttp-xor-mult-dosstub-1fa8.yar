rule TTP_XOR_MULT_DOSStub_1fa8 {
  strings:
    $key_1fa8 = { 4b c0 [2] 3f d8 [2] 78 da [2] 3f cb [2] 71 c7 [2] 7d cd [2] 6a c6 [2] 71 88 [2] 4c }

  condition:
    any of them
}