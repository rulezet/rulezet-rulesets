rule TTP_XOR_MULT_DOSStub_0f37 {
  strings:
    $key_0f37 = { 5b 5f [2] 2f 47 [2] 68 45 [2] 2f 54 [2] 61 58 [2] 6d 52 [2] 7a 59 [2] 61 17 [2] 5c }

  condition:
    any of them
}