rule TTP_XOR_MULT_DOSStub_6d19 {
  strings:
    $key_6d19 = { 39 71 [2] 4d 69 [2] 0a 6b [2] 4d 7a [2] 03 76 [2] 0f 7c [2] 18 77 [2] 03 39 [2] 3e }

  condition:
    any of them
}