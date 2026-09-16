rule TTP_XOR_MULT_DOSStub_6f50 {
  strings:
    $key_6f50 = { 3b 38 [2] 4f 20 [2] 08 22 [2] 4f 33 [2] 01 3f [2] 0d 35 [2] 1a 3e [2] 01 70 [2] 3c }

  condition:
    any of them
}