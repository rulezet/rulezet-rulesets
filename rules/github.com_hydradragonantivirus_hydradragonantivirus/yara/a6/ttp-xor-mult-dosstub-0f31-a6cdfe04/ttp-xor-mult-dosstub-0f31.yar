rule TTP_XOR_MULT_DOSStub_0f31 {
  strings:
    $key_0f31 = { 5b 59 [2] 2f 41 [2] 68 43 [2] 2f 52 [2] 61 5e [2] 6d 54 [2] 7a 5f [2] 61 11 [2] 5c }

  condition:
    any of them
}