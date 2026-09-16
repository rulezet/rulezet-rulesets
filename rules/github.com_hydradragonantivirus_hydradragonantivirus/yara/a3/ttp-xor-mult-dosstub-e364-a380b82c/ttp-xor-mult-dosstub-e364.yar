rule TTP_XOR_MULT_DOSStub_e364 {
  strings:
    $key_e364 = { b7 0c [2] c3 14 [2] 84 16 [2] c3 07 [2] 8d 0b [2] 81 01 [2] 96 0a [2] 8d 44 [2] b0 }

  condition:
    any of them
}