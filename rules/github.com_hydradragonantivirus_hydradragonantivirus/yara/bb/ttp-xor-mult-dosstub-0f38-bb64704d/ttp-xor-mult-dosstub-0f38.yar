rule TTP_XOR_MULT_DOSStub_0f38 {
  strings:
    $key_0f38 = { 5b 50 [2] 2f 48 [2] 68 4a [2] 2f 5b [2] 61 57 [2] 6d 5d [2] 7a 56 [2] 61 18 [2] 5c }

  condition:
    any of them
}