rule TTP_XOR_MULT_DOSStub_3cf0 {
  strings:
    $key_3cf0 = { 68 98 [2] 1c 80 [2] 5b 82 [2] 1c 93 [2] 52 9f [2] 5e 95 [2] 49 9e [2] 52 d0 [2] 6f }

  condition:
    any of them
}