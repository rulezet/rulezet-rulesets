rule TTP_XOR_MULT_DOSStub_6f60 {
  strings:
    $key_6f60 = { 3b 08 [2] 4f 10 [2] 08 12 [2] 4f 03 [2] 01 0f [2] 0d 05 [2] 1a 0e [2] 01 40 [2] 3c }

  condition:
    any of them
}