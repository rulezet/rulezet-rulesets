rule TTP_XOR_MULT_DOSStub_eaa7 {
  strings:
    $key_eaa7 = { be cf [2] ca d7 [2] 8d d5 [2] ca c4 [2] 84 c8 [2] 88 c2 [2] 9f c9 [2] 84 87 [2] b9 }

  condition:
    any of them
}