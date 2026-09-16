rule TTP_XOR_MULT_DOSStub_7b12 {
  strings:
    $key_7b12 = { 2f 7a [2] 5b 62 [2] 1c 60 [2] 5b 71 [2] 15 7d [2] 19 77 [2] 0e 7c [2] 15 32 [2] 28 }

  condition:
    any of them
}