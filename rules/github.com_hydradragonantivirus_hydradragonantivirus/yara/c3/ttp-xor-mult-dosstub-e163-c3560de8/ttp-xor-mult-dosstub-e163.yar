rule TTP_XOR_MULT_DOSStub_e163 {
  strings:
    $key_e163 = { b5 0b [2] c1 13 [2] 86 11 [2] c1 00 [2] 8f 0c [2] 83 06 [2] 94 0d [2] 8f 43 [2] b2 }

  condition:
    any of them
}