rule TTP_XOR_MULT_DOSStub_5f1b {
  strings:
    $key_5f1b = { 0b 73 [2] 7f 6b [2] 38 69 [2] 7f 78 [2] 31 74 [2] 3d 7e [2] 2a 75 [2] 31 3b [2] 0c }

  condition:
    any of them
}