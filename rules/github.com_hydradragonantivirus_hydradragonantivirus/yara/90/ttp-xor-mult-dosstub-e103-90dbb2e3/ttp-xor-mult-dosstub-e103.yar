rule TTP_XOR_MULT_DOSStub_e103 {
  strings:
    $key_e103 = { b5 6b [2] c1 73 [2] 86 71 [2] c1 60 [2] 8f 6c [2] 83 66 [2] 94 6d [2] 8f 23 [2] b2 }

  condition:
    any of them
}