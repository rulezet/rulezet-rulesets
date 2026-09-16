rule TTP_XOR_MULT_DOSStub_6fe1 {
  strings:
    $key_6fe1 = { 3b 89 [2] 4f 91 [2] 08 93 [2] 4f 82 [2] 01 8e [2] 0d 84 [2] 1a 8f [2] 01 c1 [2] 3c }

  condition:
    any of them
}