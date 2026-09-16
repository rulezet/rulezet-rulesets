rule TTP_XOR_MULT_DOSStub_2558 {
  strings:
    $key_2558 = { 71 30 [2] 05 28 [2] 42 2a [2] 05 3b [2] 4b 37 [2] 47 3d [2] 50 36 [2] 4b 78 [2] 76 }

  condition:
    any of them
}