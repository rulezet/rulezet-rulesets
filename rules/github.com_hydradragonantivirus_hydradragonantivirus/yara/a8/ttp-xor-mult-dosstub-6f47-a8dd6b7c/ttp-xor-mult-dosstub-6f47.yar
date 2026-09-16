rule TTP_XOR_MULT_DOSStub_6f47 {
  strings:
    $key_6f47 = { 3b 2f [2] 4f 37 [2] 08 35 [2] 4f 24 [2] 01 28 [2] 0d 22 [2] 1a 29 [2] 01 67 [2] 3c }

  condition:
    any of them
}