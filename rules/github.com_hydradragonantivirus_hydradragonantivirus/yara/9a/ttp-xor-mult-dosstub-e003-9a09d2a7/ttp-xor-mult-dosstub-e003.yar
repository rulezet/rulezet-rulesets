rule TTP_XOR_MULT_DOSStub_e003 {
  strings:
    $key_e003 = { b4 6b [2] c0 73 [2] 87 71 [2] c0 60 [2] 8e 6c [2] 82 66 [2] 95 6d [2] 8e 23 [2] b3 }

  condition:
    any of them
}