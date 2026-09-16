rule TTP_XOR_MULT_DOSStub_2508 {
  strings:
    $key_2508 = { 71 60 [2] 05 78 [2] 42 7a [2] 05 6b [2] 4b 67 [2] 47 6d [2] 50 66 [2] 4b 28 [2] 76 }

  condition:
    any of them
}