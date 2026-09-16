rule TTP_XOR_MULT_DOSStub_7153 {
  strings:
    $key_7153 = { 25 3b [2] 51 23 [2] 16 21 [2] 51 30 [2] 1f 3c [2] 13 36 [2] 04 3d [2] 1f 73 [2] 22 }

  condition:
    any of them
}