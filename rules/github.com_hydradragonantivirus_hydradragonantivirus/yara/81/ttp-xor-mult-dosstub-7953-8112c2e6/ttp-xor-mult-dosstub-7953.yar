rule TTP_XOR_MULT_DOSStub_7953 {
  strings:
    $key_7953 = { 2d 3b [2] 59 23 [2] 1e 21 [2] 59 30 [2] 17 3c [2] 1b 36 [2] 0c 3d [2] 17 73 [2] 2a }

  condition:
    any of them
}