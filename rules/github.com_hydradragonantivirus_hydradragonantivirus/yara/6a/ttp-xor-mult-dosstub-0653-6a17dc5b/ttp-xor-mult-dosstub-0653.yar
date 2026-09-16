rule TTP_XOR_MULT_DOSStub_0653 {
  strings:
    $key_0653 = { 52 3b [2] 26 23 [2] 61 21 [2] 26 30 [2] 68 3c [2] 64 36 [2] 73 3d [2] 68 73 [2] 55 }

  condition:
    any of them
}