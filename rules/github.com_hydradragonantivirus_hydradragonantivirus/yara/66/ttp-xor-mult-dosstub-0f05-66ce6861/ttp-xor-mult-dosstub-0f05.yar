rule TTP_XOR_MULT_DOSStub_0f05 {
  strings:
    $key_0f05 = { 5b 6d [2] 2f 75 [2] 68 77 [2] 2f 66 [2] 61 6a [2] 6d 60 [2] 7a 6b [2] 61 25 [2] 5c }

  condition:
    any of them
}