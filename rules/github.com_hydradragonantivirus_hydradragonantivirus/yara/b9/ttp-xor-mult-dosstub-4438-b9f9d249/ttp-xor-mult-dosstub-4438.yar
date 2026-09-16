rule TTP_XOR_MULT_DOSStub_4438 {
  strings:
    $key_4438 = { 10 50 [2] 64 48 [2] 23 4a [2] 64 5b [2] 2a 57 [2] 26 5d [2] 31 56 [2] 2a 18 [2] 17 }

  condition:
    any of them
}