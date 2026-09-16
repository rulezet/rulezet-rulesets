rule TTP_XOR_MULT_DOSStub_0a39 {
  strings:
    $key_0a39 = { 5e 51 [2] 2a 49 [2] 6d 4b [2] 2a 5a [2] 64 56 [2] 68 5c [2] 7f 57 [2] 64 19 [2] 59 }

  condition:
    any of them
}