rule TTP_XOR_MULT_DOSStub_4f7b {
  strings:
    $key_4f7b = { 1b 13 [2] 6f 0b [2] 28 09 [2] 6f 18 [2] 21 14 [2] 2d 1e [2] 3a 15 [2] 21 5b [2] 1c }

  condition:
    any of them
}