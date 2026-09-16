rule TTP_XOR_MULT_DOSStub_4433 {
  strings:
    $key_4433 = { 10 5b [2] 64 43 [2] 23 41 [2] 64 50 [2] 2a 5c [2] 26 56 [2] 31 5d [2] 2a 13 [2] 17 }

  condition:
    any of them
}