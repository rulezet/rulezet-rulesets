rule TTP_XOR_MULT_DOSStub_1f76 {
  strings:
    $key_1f76 = { 4b 1e [2] 3f 06 [2] 78 04 [2] 3f 15 [2] 71 19 [2] 7d 13 [2] 6a 18 [2] 71 56 [2] 4c }

  condition:
    any of them
}