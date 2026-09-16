rule TTP_XOR_MULT_DOSStub_6f57 {
  strings:
    $key_6f57 = { 3b 3f [2] 4f 27 [2] 08 25 [2] 4f 34 [2] 01 38 [2] 0d 32 [2] 1a 39 [2] 01 77 [2] 3c }

  condition:
    any of them
}