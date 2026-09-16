rule TTP_XOR_MULT_DOSStub_2555 {
  strings:
    $key_2555 = { 71 3d [2] 05 25 [2] 42 27 [2] 05 36 [2] 4b 3a [2] 47 30 [2] 50 3b [2] 4b 75 [2] 76 }

  condition:
    any of them
}