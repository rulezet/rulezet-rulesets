rule TTP_XOR_MULT_DOSStub_0f76 {
  strings:
    $key_0f76 = { 5b 1e [2] 2f 06 [2] 68 04 [2] 2f 15 [2] 61 19 [2] 6d 13 [2] 7a 18 [2] 61 56 [2] 5c }

  condition:
    any of them
}