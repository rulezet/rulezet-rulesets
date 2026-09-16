rule TTP_XOR_MULT_DOSStub_6953 {
  strings:
    $key_6953 = { 3d 3b [2] 49 23 [2] 0e 21 [2] 49 30 [2] 07 3c [2] 0b 36 [2] 1c 3d [2] 07 73 [2] 3a }

  condition:
    any of them
}