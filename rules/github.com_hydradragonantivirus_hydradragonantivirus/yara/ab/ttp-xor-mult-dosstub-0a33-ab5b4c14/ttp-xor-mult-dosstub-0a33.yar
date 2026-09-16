rule TTP_XOR_MULT_DOSStub_0a33 {
  strings:
    $key_0a33 = { 5e 5b [2] 2a 43 [2] 6d 41 [2] 2a 50 [2] 64 5c [2] 68 56 [2] 7f 5d [2] 64 13 [2] 59 }

  condition:
    any of them
}