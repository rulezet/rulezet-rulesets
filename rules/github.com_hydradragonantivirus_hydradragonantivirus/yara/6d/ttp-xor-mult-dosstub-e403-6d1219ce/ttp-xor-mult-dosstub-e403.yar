rule TTP_XOR_MULT_DOSStub_e403 {
  strings:
    $key_e403 = { b0 6b [2] c4 73 [2] 83 71 [2] c4 60 [2] 8a 6c [2] 86 66 [2] 91 6d [2] 8a 23 [2] b7 }

  condition:
    any of them
}