rule TTP_XOR_MULT_DOSStub_0b19 {
  strings:
    $key_0b19 = { 5f 71 [2] 2b 69 [2] 6c 6b [2] 2b 7a [2] 65 76 [2] 69 7c [2] 7e 77 [2] 65 39 [2] 58 }

  condition:
    any of them
}