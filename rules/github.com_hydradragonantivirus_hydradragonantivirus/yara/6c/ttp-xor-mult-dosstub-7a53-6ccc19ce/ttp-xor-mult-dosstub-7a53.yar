rule TTP_XOR_MULT_DOSStub_7a53 {
  strings:
    $key_7a53 = { 2e 3b [2] 5a 23 [2] 1d 21 [2] 5a 30 [2] 14 3c [2] 18 36 [2] 0f 3d [2] 14 73 [2] 29 }

  condition:
    any of them
}