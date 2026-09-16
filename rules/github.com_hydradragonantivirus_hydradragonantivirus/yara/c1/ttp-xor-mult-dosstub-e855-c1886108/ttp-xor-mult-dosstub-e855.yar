rule TTP_XOR_MULT_DOSStub_e855 {
  strings:
    $key_e855 = { bc 3d [2] c8 25 [2] 8f 27 [2] c8 36 [2] 86 3a [2] 8a 30 [2] 9d 3b [2] 86 75 [2] bb }

  condition:
    any of them
}