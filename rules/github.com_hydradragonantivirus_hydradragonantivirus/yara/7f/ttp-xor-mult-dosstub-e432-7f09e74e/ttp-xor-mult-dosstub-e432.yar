rule TTP_XOR_MULT_DOSStub_e432 {
  strings:
    $key_e432 = { b0 5a [2] c4 42 [2] 83 40 [2] c4 51 [2] 8a 5d [2] 86 57 [2] 91 5c [2] 8a 12 [2] b7 }

  condition:
    any of them
}