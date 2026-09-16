rule TTP_XOR_MULT_DOSStub_e803 {
  strings:
    $key_e803 = { bc 6b [2] c8 73 [2] 8f 71 [2] c8 60 [2] 86 6c [2] 8a 66 [2] 9d 6d [2] 86 23 [2] bb }

  condition:
    any of them
}