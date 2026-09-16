rule TTP_XOR_MULT_DOSStub_3005 {
  strings:
    $key_3005 = { 64 6d [2] 10 75 [2] 57 77 [2] 10 66 [2] 5e 6a [2] 52 60 [2] 45 6b [2] 5e 25 [2] 63 }

  condition:
    any of them
}