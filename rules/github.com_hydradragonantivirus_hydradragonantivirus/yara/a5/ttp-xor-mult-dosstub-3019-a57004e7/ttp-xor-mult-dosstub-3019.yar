rule TTP_XOR_MULT_DOSStub_3019 {
  strings:
    $key_3019 = { 64 71 [2] 10 69 [2] 57 6b [2] 10 7a [2] 5e 76 [2] 52 7c [2] 45 77 [2] 5e 39 [2] 63 }

  condition:
    any of them
}