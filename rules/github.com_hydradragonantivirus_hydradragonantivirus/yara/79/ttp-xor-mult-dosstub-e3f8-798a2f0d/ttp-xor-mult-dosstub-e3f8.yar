rule TTP_XOR_MULT_DOSStub_e3f8 {
  strings:
    $key_e3f8 = { b7 90 [2] c3 88 [2] 84 8a [2] c3 9b [2] 8d 97 [2] 81 9d [2] 96 96 [2] 8d d8 [2] b0 }

  condition:
    any of them
}