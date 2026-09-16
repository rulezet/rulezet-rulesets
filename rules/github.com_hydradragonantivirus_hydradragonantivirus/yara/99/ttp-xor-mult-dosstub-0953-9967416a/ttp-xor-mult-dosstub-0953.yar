rule TTP_XOR_MULT_DOSStub_0953 {
  strings:
    $key_0953 = { 5d 3b [2] 29 23 [2] 6e 21 [2] 29 30 [2] 67 3c [2] 6b 36 [2] 7c 3d [2] 67 73 [2] 5a }

  condition:
    any of them
}