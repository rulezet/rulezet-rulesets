rule TTP_XOR_MULT_DOSStub_2f19 {
  strings:
    $key_2f19 = { 7b 71 [2] 0f 69 [2] 48 6b [2] 0f 7a [2] 41 76 [2] 4d 7c [2] 5a 77 [2] 41 39 [2] 7c }

  condition:
    any of them
}