rule TTP_XOR_MULT_DOSStub_6b12 {
  strings:
    $key_6b12 = { 3f 7a [2] 4b 62 [2] 0c 60 [2] 4b 71 [2] 05 7d [2] 09 77 [2] 1e 7c [2] 05 32 [2] 38 }

  condition:
    any of them
}