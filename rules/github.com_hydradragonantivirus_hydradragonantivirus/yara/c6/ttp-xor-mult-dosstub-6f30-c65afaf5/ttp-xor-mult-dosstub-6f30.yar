rule TTP_XOR_MULT_DOSStub_6f30 {
  strings:
    $key_6f30 = { 3b 58 [2] 4f 40 [2] 08 42 [2] 4f 53 [2] 01 5f [2] 0d 55 [2] 1a 5e [2] 01 10 [2] 3c }

  condition:
    any of them
}