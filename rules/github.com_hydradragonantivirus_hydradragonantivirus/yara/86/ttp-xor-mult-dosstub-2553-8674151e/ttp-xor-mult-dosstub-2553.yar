rule TTP_XOR_MULT_DOSStub_2553 {
  strings:
    $key_2553 = { 71 3b [2] 05 23 [2] 42 21 [2] 05 30 [2] 4b 3c [2] 47 36 [2] 50 3d [2] 4b 73 [2] 76 }

  condition:
    any of them
}