rule TTP_XOR_MULT_DOSStub_5b19 {
  strings:
    $key_5b19 = { 0f 71 [2] 7b 69 [2] 3c 6b [2] 7b 7a [2] 35 76 [2] 39 7c [2] 2e 77 [2] 35 39 [2] 08 }

  condition:
    any of them
}