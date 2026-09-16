rule TTP_XOR_MULT_DOSStub_e179 {
  strings:
    $key_e179 = { b5 11 [2] c1 09 [2] 86 0b [2] c1 1a [2] 8f 16 [2] 83 1c [2] 94 17 [2] 8f 59 [2] b2 }

  condition:
    any of them
}