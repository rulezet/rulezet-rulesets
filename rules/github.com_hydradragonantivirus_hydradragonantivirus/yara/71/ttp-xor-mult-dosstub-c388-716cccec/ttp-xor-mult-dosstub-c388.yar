rule TTP_XOR_MULT_DOSStub_c388 {
  strings:
    $key_c388 = { 97 e0 [2] e3 f8 [2] a4 fa [2] e3 eb [2] ad e7 [2] a1 ed [2] b6 e6 [2] ad a8 [2] 90 }

  condition:
    any of them
}