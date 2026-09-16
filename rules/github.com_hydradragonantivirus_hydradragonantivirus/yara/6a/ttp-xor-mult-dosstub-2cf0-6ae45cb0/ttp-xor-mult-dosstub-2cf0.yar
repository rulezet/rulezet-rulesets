rule TTP_XOR_MULT_DOSStub_2cf0 {
  strings:
    $key_2cf0 = { 78 98 [2] 0c 80 [2] 4b 82 [2] 0c 93 [2] 42 9f [2] 4e 95 [2] 59 9e [2] 42 d0 [2] 7f }

  condition:
    any of them
}