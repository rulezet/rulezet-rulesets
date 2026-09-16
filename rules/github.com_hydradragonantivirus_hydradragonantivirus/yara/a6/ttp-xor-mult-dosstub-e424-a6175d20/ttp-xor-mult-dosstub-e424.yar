rule TTP_XOR_MULT_DOSStub_e424 {
  strings:
    $key_e424 = { b0 4c [2] c4 54 [2] 83 56 [2] c4 47 [2] 8a 4b [2] 86 41 [2] 91 4a [2] 8a 04 [2] b7 }

  condition:
    any of them
}