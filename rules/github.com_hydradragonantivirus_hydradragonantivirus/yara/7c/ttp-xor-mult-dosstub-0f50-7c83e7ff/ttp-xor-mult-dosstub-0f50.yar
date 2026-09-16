rule TTP_XOR_MULT_DOSStub_0f50 {
  strings:
    $key_0f50 = { 5b 38 [2] 2f 20 [2] 68 22 [2] 2f 33 [2] 61 3f [2] 6d 35 [2] 7a 3e [2] 61 70 [2] 5c }

  condition:
    any of them
}