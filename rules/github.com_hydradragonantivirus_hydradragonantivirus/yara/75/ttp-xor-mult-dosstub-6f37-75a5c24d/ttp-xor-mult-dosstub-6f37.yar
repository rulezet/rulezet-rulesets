rule TTP_XOR_MULT_DOSStub_6f37 {
  strings:
    $key_6f37 = { 3b 5f [2] 4f 47 [2] 08 45 [2] 4f 54 [2] 01 58 [2] 0d 52 [2] 1a 59 [2] 01 17 [2] 3c }

  condition:
    any of them
}