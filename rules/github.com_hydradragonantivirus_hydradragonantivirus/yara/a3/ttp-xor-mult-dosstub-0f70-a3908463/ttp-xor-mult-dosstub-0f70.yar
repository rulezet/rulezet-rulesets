rule TTP_XOR_MULT_DOSStub_0f70 {
  strings:
    $key_0f70 = { 5b 18 [2] 2f 00 [2] 68 02 [2] 2f 13 [2] 61 1f [2] 6d 15 [2] 7a 1e [2] 61 50 [2] 5c }

  condition:
    any of them
}