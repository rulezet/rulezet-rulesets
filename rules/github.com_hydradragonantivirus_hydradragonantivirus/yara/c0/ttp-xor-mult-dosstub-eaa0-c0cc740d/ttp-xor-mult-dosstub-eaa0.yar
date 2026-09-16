rule TTP_XOR_MULT_DOSStub_eaa0 {
  strings:
    $key_eaa0 = { be c8 [2] ca d0 [2] 8d d2 [2] ca c3 [2] 84 cf [2] 88 c5 [2] 9f ce [2] 84 80 [2] b9 }

  condition:
    any of them
}