rule TTP_XOR_MULT_DOSStub_e4ee {
  strings:
    $key_e4ee = { b0 86 [2] c4 9e [2] 83 9c [2] c4 8d [2] 8a 81 [2] 86 8b [2] 91 80 [2] 8a ce [2] b7 }

  condition:
    any of them
}