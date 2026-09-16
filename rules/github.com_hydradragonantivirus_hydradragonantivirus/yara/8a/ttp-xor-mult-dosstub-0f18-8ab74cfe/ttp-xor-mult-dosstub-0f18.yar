rule TTP_XOR_MULT_DOSStub_0f18 {
  strings:
    $key_0f18 = { 5b 70 [2] 2f 68 [2] 68 6a [2] 2f 7b [2] 61 77 [2] 6d 7d [2] 7a 76 [2] 61 38 [2] 5c }

  condition:
    any of them
}