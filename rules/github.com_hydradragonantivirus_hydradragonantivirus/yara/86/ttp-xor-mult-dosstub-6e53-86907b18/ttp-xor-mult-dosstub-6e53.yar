rule TTP_XOR_MULT_DOSStub_6e53 {
  strings:
    $key_6e53 = { 3a 3b [2] 4e 23 [2] 09 21 [2] 4e 30 [2] 00 3c [2] 0c 36 [2] 1b 3d [2] 00 73 [2] 3d }

  condition:
    any of them
}