rule TTP_XOR_MULT_DOSStub_3b12 {
  strings:
    $key_3b12 = { 6f 7a [2] 1b 62 [2] 5c 60 [2] 1b 71 [2] 55 7d [2] 59 77 [2] 4e 7c [2] 55 32 [2] 68 }

  condition:
    any of them
}