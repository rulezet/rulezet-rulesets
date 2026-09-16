rule TTP_XOR_MULT_DOSStub_0a19 {
  strings:
    $key_0a19 = { 5e 71 [2] 2a 69 [2] 6d 6b [2] 2a 7a [2] 64 76 [2] 68 7c [2] 7f 77 [2] 64 39 [2] 59 }

  condition:
    any of them
}