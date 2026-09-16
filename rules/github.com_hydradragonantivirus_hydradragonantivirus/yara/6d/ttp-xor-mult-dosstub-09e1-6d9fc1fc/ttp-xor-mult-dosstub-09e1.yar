rule TTP_XOR_MULT_DOSStub_09e1 {
  strings:
    $key_09e1 = { 5d 89 [2] 29 91 [2] 6e 93 [2] 29 82 [2] 67 8e [2] 6b 84 [2] 7c 8f [2] 67 c1 [2] 5a }

  condition:
    any of them
}