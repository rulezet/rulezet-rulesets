rule TTP_XOR_MULT_DOSStub_aa99 {
  strings:
    $key_aa99 = { fe f1 [2] 8a e9 [2] cd eb [2] 8a fa [2] c4 f6 [2] c8 fc [2] df f7 [2] c4 b9 [2] f9 }

  condition:
    any of them
}