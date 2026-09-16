rule TTP_XOR_MULT_DOSStub_5f4b {
  strings:
    $key_5f4b = { 0b 23 [2] 7f 3b [2] 38 39 [2] 7f 28 [2] 31 24 [2] 3d 2e [2] 2a 25 [2] 31 6b [2] 0c }

  condition:
    any of them
}