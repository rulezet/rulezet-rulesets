rule TTP_XOR_MULT_DOSStub_a153 {
  strings:
    $key_a153 = { f5 3b [2] 81 23 [2] c6 21 [2] 81 30 [2] cf 3c [2] c3 36 [2] d4 3d [2] cf 73 [2] f2 }

  condition:
    any of them
}