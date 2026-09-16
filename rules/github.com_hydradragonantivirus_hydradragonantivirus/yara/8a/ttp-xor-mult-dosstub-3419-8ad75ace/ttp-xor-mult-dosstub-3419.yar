rule TTP_XOR_MULT_DOSStub_3419 {
  strings:
    $key_3419 = { 60 71 [2] 14 69 [2] 53 6b [2] 14 7a [2] 5a 76 [2] 56 7c [2] 41 77 [2] 5a 39 [2] 67 }

  condition:
    any of them
}