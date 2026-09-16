rule TTP_XOR_MULT_DOSStub_921b {
  strings:
    $key_921b = { c6 73 [2] b2 6b [2] f5 69 [2] b2 78 [2] fc 74 [2] f0 7e [2] e7 75 [2] fc 3b [2] c1 }

  condition:
    any of them
}