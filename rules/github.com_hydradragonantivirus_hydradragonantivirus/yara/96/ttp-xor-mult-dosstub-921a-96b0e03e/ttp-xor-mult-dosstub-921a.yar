rule TTP_XOR_MULT_DOSStub_921a {
  strings:
    $key_921a = { c6 72 [2] b2 6a [2] f5 68 [2] b2 79 [2] fc 75 [2] f0 7f [2] e7 74 [2] fc 3a [2] c1 }

  condition:
    any of them
}