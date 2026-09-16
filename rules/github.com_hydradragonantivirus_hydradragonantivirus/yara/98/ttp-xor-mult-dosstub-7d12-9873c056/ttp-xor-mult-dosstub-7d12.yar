rule TTP_XOR_MULT_DOSStub_7d12 {
  strings:
    $key_7d12 = { 29 7a [2] 5d 62 [2] 1a 60 [2] 5d 71 [2] 13 7d [2] 1f 77 [2] 08 7c [2] 13 32 [2] 2e }

  condition:
    any of them
}