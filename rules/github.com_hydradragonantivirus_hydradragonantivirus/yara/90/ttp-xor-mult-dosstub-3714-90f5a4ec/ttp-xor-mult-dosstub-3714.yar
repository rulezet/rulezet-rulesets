rule TTP_XOR_MULT_DOSStub_3714 {
  strings:
    $key_3714 = { 63 7c [2] 17 64 [2] 50 66 [2] 17 77 [2] 59 7b [2] 55 71 [2] 42 7a [2] 59 34 [2] 64 }

  condition:
    any of them
}