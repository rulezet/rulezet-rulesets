rule TTP_XOR_MULT_DOSStub_e603 {
  strings:
    $key_e603 = { b2 6b [2] c6 73 [2] 81 71 [2] c6 60 [2] 88 6c [2] 84 66 [2] 93 6d [2] 88 23 [2] b5 }

  condition:
    any of them
}