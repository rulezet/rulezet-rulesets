rule TTP_XOR_MULT_DOSStub_5b12 {
  strings:
    $key_5b12 = { 0f 7a [2] 7b 62 [2] 3c 60 [2] 7b 71 [2] 35 7d [2] 39 77 [2] 2e 7c [2] 35 32 [2] 08 }

  condition:
    any of them
}