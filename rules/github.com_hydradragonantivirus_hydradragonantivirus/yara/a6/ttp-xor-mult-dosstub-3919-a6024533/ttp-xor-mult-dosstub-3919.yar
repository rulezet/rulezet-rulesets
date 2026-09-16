rule TTP_XOR_MULT_DOSStub_3919 {
  strings:
    $key_3919 = { 6d 71 [2] 19 69 [2] 5e 6b [2] 19 7a [2] 57 76 [2] 5b 7c [2] 4c 77 [2] 57 39 [2] 6a }

  condition:
    any of them
}