rule TTP_XOR_MULT_DOSStub_e264 {
  strings:
    $key_e264 = { b6 0c [2] c2 14 [2] 85 16 [2] c2 07 [2] 8c 0b [2] 80 01 [2] 97 0a [2] 8c 44 [2] b1 }

  condition:
    any of them
}