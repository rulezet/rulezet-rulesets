rule TTP_XOR_MULT_DOSStub_e1ee {
  strings:
    $key_e1ee = { b5 86 [2] c1 9e [2] 86 9c [2] c1 8d [2] 8f 81 [2] 83 8b [2] 94 80 [2] 8f ce [2] b2 }

  condition:
    any of them
}