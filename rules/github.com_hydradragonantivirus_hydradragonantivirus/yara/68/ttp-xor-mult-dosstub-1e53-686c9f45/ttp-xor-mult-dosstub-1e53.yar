rule TTP_XOR_MULT_DOSStub_1e53 {
  strings:
    $key_1e53 = { 4a 3b [2] 3e 23 [2] 79 21 [2] 3e 30 [2] 70 3c [2] 7c 36 [2] 6b 3d [2] 70 73 [2] 4d }

  condition:
    any of them
}