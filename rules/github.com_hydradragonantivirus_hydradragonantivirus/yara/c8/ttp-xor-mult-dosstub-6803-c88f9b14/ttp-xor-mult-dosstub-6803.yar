rule TTP_XOR_MULT_DOSStub_6803 {
  strings:
    $key_6803 = { 3c 6b [2] 48 73 [2] 0f 71 [2] 48 60 [2] 06 6c [2] 0a 66 [2] 1d 6d [2] 06 23 [2] 3b }

  condition:
    any of them
}