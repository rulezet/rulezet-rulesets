rule TTP_XOR_MULT_DOSStub_4fe0 {
  strings:
    $key_4fe0 = { 1b 88 [2] 6f 90 [2] 28 92 [2] 6f 83 [2] 21 8f [2] 2d 85 [2] 3a 8e [2] 21 c0 [2] 1c }

  condition:
    any of them
}