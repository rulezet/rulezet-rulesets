rule TTP_XOR_MULT_DOSStub_1f7b {
  strings:
    $key_1f7b = { 4b 13 [2] 3f 0b [2] 78 09 [2] 3f 18 [2] 71 14 [2] 7d 1e [2] 6a 15 [2] 71 5b [2] 4c }

  condition:
    any of them
}