rule TTP_XOR_MULT_DOSStub_7412 {
  strings:
    $key_7412 = { 20 7a [2] 54 62 [2] 13 60 [2] 54 71 [2] 1a 7d [2] 16 77 [2] 01 7c [2] 1a 32 [2] 27 }

  condition:
    any of them
}