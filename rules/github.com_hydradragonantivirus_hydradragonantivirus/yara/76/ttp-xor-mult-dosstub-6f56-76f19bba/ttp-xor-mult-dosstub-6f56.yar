rule TTP_XOR_MULT_DOSStub_6f56 {
  strings:
    $key_6f56 = { 3b 3e [2] 4f 26 [2] 08 24 [2] 4f 35 [2] 01 39 [2] 0d 33 [2] 1a 38 [2] 01 76 [2] 3c }

  condition:
    any of them
}