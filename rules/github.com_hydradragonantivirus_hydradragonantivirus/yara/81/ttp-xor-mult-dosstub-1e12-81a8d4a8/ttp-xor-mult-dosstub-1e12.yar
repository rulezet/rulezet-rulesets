rule TTP_XOR_MULT_DOSStub_1e12 {
  strings:
    $key_1e12 = { 4a 7a [2] 3e 62 [2] 79 60 [2] 3e 71 [2] 70 7d [2] 7c 77 [2] 6b 7c [2] 70 32 [2] 4d }

  condition:
    any of them
}