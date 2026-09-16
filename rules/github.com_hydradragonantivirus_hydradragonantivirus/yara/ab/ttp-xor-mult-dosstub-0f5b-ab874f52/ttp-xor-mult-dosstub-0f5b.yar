rule TTP_XOR_MULT_DOSStub_0f5b {
  strings:
    $key_0f5b = { 5b 33 [2] 2f 2b [2] 68 29 [2] 2f 38 [2] 61 34 [2] 6d 3e [2] 7a 35 [2] 61 7b [2] 5c }

  condition:
    any of them
}