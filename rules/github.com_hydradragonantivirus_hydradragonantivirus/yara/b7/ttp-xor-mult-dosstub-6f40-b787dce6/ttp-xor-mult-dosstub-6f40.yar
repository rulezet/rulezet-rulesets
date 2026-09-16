rule TTP_XOR_MULT_DOSStub_6f40 {
  strings:
    $key_6f40 = { 3b 28 [2] 4f 30 [2] 08 32 [2] 4f 23 [2] 01 2f [2] 0d 25 [2] 1a 2e [2] 01 60 [2] 3c }

  condition:
    any of them
}