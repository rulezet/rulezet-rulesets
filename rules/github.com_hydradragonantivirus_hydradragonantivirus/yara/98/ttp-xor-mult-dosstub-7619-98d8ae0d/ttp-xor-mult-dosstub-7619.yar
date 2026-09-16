rule TTP_XOR_MULT_DOSStub_7619 {
  strings:
    $key_7619 = { 22 71 [2] 56 69 [2] 11 6b [2] 56 7a [2] 18 76 [2] 14 7c [2] 03 77 [2] 18 39 [2] 25 }

  condition:
    any of them
}