rule TTP_XOR_MULT_DOSStub_0f26 {
  strings:
    $key_0f26 = { 5b 4e [2] 2f 56 [2] 68 54 [2] 2f 45 [2] 61 49 [2] 6d 43 [2] 7a 48 [2] 61 06 [2] 5c }

  condition:
    any of them
}