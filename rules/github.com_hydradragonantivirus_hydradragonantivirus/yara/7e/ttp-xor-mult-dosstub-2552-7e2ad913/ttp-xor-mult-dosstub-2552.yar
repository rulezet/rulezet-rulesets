rule TTP_XOR_MULT_DOSStub_2552 {
  strings:
    $key_2552 = { 71 3a [2] 05 22 [2] 42 20 [2] 05 31 [2] 4b 3d [2] 47 37 [2] 50 3c [2] 4b 72 [2] 76 }

  condition:
    any of them
}