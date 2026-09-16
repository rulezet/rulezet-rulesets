rule TTP_XOR_MULT_DOSStub_3e12 {
  strings:
    $key_3e12 = { 6a 7a [2] 1e 62 [2] 59 60 [2] 1e 71 [2] 50 7d [2] 5c 77 [2] 4b 7c [2] 50 32 [2] 6d }

  condition:
    any of them
}