rule TTP_XOR_MULT_DOSStub_6903 {
  strings:
    $key_6903 = { 3d 6b [2] 49 73 [2] 0e 71 [2] 49 60 [2] 07 6c [2] 0b 66 [2] 1c 6d [2] 07 23 [2] 3a }

  condition:
    any of them
}