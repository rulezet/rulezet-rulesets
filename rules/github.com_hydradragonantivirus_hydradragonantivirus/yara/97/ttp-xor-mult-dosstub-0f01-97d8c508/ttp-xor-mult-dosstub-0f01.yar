rule TTP_XOR_MULT_DOSStub_0f01 {
  strings:
    $key_0f01 = { 5b 69 [2] 2f 71 [2] 68 73 [2] 2f 62 [2] 61 6e [2] 6d 64 [2] 7a 6f [2] 61 21 [2] 5c }

  condition:
    any of them
}