rule TTP_XOR_MULT_DOSStub_0f51 {
  strings:
    $key_0f51 = { 5b 39 [2] 2f 21 [2] 68 23 [2] 2f 32 [2] 61 3e [2] 6d 34 [2] 7a 3f [2] 61 71 [2] 5c }

  condition:
    any of them
}