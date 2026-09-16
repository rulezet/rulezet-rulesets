rule TTP_XOR_MULT_DOSStub_e664 {
  strings:
    $key_e664 = { b2 0c [2] c6 14 [2] 81 16 [2] c6 07 [2] 88 0b [2] 84 01 [2] 93 0a [2] 88 44 [2] b5 }

  condition:
    any of them
}