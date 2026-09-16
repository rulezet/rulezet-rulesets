rule TTP_XOR_MULT_DOSStub_0f19 {
  strings:
    $key_0f19 = { 5b 71 [2] 2f 69 [2] 68 6b [2] 2f 7a [2] 61 76 [2] 6d 7c [2] 7a 77 [2] 61 39 [2] 5c }

  condition:
    any of them
}