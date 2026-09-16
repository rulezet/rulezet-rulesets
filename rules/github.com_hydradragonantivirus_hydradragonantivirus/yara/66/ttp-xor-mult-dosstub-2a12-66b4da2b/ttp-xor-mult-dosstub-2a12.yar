rule TTP_XOR_MULT_DOSStub_2a12 {
  strings:
    $key_2a12 = { 7e 7a [2] 0a 62 [2] 4d 60 [2] 0a 71 [2] 44 7d [2] 48 77 [2] 5f 7c [2] 44 32 [2] 79 }

  condition:
    any of them
}