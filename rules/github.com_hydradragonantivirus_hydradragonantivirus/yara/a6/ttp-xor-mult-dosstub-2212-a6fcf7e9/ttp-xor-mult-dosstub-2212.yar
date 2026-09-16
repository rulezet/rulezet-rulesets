rule TTP_XOR_MULT_DOSStub_2212 {
  strings:
    $key_2212 = { 76 7a [2] 02 62 [2] 45 60 [2] 02 71 [2] 4c 7d [2] 40 77 [2] 57 7c [2] 4c 32 [2] 71 }

  condition:
    any of them
}