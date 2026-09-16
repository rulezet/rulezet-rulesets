rule TTP_XOR_MULT_DOSStub_0e12 {
  strings:
    $key_0e12 = { 5a 7a [2] 2e 62 [2] 69 60 [2] 2e 71 [2] 60 7d [2] 6c 77 [2] 7b 7c [2] 60 32 [2] 5d }

  condition:
    any of them
}