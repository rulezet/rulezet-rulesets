rule TTP_XOR_MULT_DOSStub_6ff0 {
  strings:
    $key_6ff0 = { 3b 98 [2] 4f 80 [2] 08 82 [2] 4f 93 [2] 01 9f [2] 0d 95 [2] 1a 9e [2] 01 d0 [2] 3c }

  condition:
    any of them
}