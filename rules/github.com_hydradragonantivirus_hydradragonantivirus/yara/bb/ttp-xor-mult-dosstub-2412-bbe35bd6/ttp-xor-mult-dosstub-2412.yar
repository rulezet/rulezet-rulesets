rule TTP_XOR_MULT_DOSStub_2412 {
  strings:
    $key_2412 = { 70 7a [2] 04 62 [2] 43 60 [2] 04 71 [2] 4a 7d [2] 46 77 [2] 51 7c [2] 4a 32 [2] 77 }

  condition:
    any of them
}