rule TTP_XOR_MULT_DOSStub_6fe7 {
  strings:
    $key_6fe7 = { 3b 8f [2] 4f 97 [2] 08 95 [2] 4f 84 [2] 01 88 [2] 0d 82 [2] 1a 89 [2] 01 c7 [2] 3c }

  condition:
    any of them
}