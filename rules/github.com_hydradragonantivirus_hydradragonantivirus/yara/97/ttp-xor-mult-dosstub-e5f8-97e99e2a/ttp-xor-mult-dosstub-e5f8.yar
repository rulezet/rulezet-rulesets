rule TTP_XOR_MULT_DOSStub_e5f8 {
  strings:
    $key_e5f8 = { b1 90 [2] c5 88 [2] 82 8a [2] c5 9b [2] 8b 97 [2] 87 9d [2] 90 96 [2] 8b d8 [2] b6 }

  condition:
    any of them
}