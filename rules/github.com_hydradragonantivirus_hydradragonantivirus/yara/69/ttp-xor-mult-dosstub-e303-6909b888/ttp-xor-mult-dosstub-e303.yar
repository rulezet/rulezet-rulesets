rule TTP_XOR_MULT_DOSStub_e303 {
  strings:
    $key_e303 = { b7 6b [2] c3 73 [2] 84 71 [2] c3 60 [2] 8d 6c [2] 81 66 [2] 96 6d [2] 8d 23 [2] b0 }

  condition:
    any of them
}