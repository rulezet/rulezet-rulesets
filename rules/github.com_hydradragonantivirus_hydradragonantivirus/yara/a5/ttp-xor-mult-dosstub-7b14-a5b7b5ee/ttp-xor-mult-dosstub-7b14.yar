rule TTP_XOR_MULT_DOSStub_7b14 {
  strings:
    $key_7b14 = { 2f 7c [2] 5b 64 [2] 1c 66 [2] 5b 77 [2] 15 7b [2] 19 71 [2] 0e 7a [2] 15 34 [2] 28 }

  condition:
    any of them
}