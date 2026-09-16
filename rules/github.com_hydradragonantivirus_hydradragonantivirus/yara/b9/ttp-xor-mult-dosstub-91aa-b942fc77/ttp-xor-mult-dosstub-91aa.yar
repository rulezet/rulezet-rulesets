rule TTP_XOR_MULT_DOSStub_91aa {
  strings:
    $key_91aa = { c5 c2 [2] b1 da [2] f6 d8 [2] b1 c9 [2] ff c5 [2] f3 cf [2] e4 c4 [2] ff 8a [2] c2 }

  condition:
    any of them
}