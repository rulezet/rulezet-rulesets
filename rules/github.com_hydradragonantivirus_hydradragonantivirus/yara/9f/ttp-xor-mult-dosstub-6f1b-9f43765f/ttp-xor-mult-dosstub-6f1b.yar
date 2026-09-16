rule TTP_XOR_MULT_DOSStub_6f1b {
  strings:
    $key_6f1b = { 3b 73 [2] 4f 6b [2] 08 69 [2] 4f 78 [2] 01 74 [2] 0d 7e [2] 1a 75 [2] 01 3b [2] 3c }

  condition:
    any of them
}