rule TTP_XOR_MULT_DOSStub_1a19 {
  strings:
    $key_1a19 = { 4e 71 [2] 3a 69 [2] 7d 6b [2] 3a 7a [2] 74 76 [2] 78 7c [2] 6f 77 [2] 74 39 [2] 49 }

  condition:
    any of them
}