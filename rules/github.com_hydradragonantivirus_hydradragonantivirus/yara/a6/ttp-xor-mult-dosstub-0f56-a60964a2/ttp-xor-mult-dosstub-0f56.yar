rule TTP_XOR_MULT_DOSStub_0f56 {
  strings:
    $key_0f56 = { 5b 3e [2] 2f 26 [2] 68 24 [2] 2f 35 [2] 61 39 [2] 6d 33 [2] 7a 38 [2] 61 76 [2] 5c }

  condition:
    any of them
}