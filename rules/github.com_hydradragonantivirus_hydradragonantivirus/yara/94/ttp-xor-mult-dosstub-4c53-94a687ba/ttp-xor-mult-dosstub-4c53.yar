rule TTP_XOR_MULT_DOSStub_4c53 {
  strings:
    $key_4c53 = { 18 3b [2] 6c 23 [2] 2b 21 [2] 6c 30 [2] 22 3c [2] 2e 36 [2] 39 3d [2] 22 73 [2] 1f }

  condition:
    any of them
}