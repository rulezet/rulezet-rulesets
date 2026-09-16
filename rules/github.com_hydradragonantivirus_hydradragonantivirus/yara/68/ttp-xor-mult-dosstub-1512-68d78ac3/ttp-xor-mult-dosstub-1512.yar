rule TTP_XOR_MULT_DOSStub_1512 {
  strings:
    $key_1512 = { 41 7a [2] 35 62 [2] 72 60 [2] 35 71 [2] 7b 7d [2] 77 77 [2] 60 7c [2] 7b 32 [2] 46 }

  condition:
    any of them
}