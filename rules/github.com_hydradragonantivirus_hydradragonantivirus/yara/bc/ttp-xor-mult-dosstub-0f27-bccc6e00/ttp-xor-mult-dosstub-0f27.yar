rule TTP_XOR_MULT_DOSStub_0f27 {
  strings:
    $key_0f27 = { 5b 4f [2] 2f 57 [2] 68 55 [2] 2f 44 [2] 61 48 [2] 6d 42 [2] 7a 49 [2] 61 07 [2] 5c }

  condition:
    any of them
}