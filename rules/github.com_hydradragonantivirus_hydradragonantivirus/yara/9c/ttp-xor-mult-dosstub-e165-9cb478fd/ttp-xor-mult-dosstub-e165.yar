rule TTP_XOR_MULT_DOSStub_e165 {
  strings:
    $key_e165 = { b5 0d [2] c1 15 [2] 86 17 [2] c1 06 [2] 8f 0a [2] 83 00 [2] 94 0b [2] 8f 45 [2] b2 }

  condition:
    any of them
}