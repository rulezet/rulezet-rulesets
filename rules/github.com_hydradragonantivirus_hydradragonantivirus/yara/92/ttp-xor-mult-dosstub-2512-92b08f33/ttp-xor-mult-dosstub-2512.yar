rule TTP_XOR_MULT_DOSStub_2512 {
  strings:
    $key_2512 = { 71 7a [2] 05 62 [2] 42 60 [2] 05 71 [2] 4b 7d [2] 47 77 [2] 50 7c [2] 4b 32 [2] 76 }

  condition:
    any of them
}