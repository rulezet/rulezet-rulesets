rule TTP_XOR_MULT_DOSStub_6f7b {
  strings:
    $key_6f7b = { 3b 13 [2] 4f 0b [2] 08 09 [2] 4f 18 [2] 01 14 [2] 0d 1e [2] 1a 15 [2] 01 5b [2] 3c }

  condition:
    any of them
}