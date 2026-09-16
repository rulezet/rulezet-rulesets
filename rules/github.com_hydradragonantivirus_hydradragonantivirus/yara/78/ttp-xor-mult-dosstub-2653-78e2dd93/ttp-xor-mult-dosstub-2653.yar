rule TTP_XOR_MULT_DOSStub_2653 {
  strings:
    $key_2653 = { 72 3b [2] 06 23 [2] 41 21 [2] 06 30 [2] 48 3c [2] 44 36 [2] 53 3d [2] 48 73 [2] 75 }

  condition:
    any of them
}