rule TTP_XOR_MULT_DOSStub_0fe0 {
  strings:
    $key_0fe0 = { 5b 88 [2] 2f 90 [2] 68 92 [2] 2f 83 [2] 61 8f [2] 6d 85 [2] 7a 8e [2] 61 c0 [2] 5c }

  condition:
    any of them
}