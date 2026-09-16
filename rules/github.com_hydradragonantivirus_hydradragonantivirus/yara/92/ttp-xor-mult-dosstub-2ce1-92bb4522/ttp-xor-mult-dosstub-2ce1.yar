rule TTP_XOR_MULT_DOSStub_2ce1 {
  strings:
    $key_2ce1 = { 78 89 [2] 0c 91 [2] 4b 93 [2] 0c 82 [2] 42 8e [2] 4e 84 [2] 59 8f [2] 42 c1 [2] 7f }

  condition:
    any of them
}