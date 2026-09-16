rule TTP_XOR_MULT_DOSStub_7c53 {
  strings:
    $key_7c53 = { 28 3b [2] 5c 23 [2] 1b 21 [2] 5c 30 [2] 12 3c [2] 1e 36 [2] 09 3d [2] 12 73 [2] 2f }

  condition:
    any of them
}