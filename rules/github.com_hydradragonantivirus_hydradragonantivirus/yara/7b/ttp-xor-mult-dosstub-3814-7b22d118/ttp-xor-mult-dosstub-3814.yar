rule TTP_XOR_MULT_DOSStub_3814 {
  strings:
    $key_3814 = { 6c 7c [2] 18 64 [2] 5f 66 [2] 18 77 [2] 56 7b [2] 5a 71 [2] 4d 7a [2] 56 34 [2] 6b }

  condition:
    any of them
}