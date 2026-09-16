rule TTP_XOR_MULT_DOSStub_a8a2 {
  strings:
    $key_a8a2 = { fc ca [2] 88 d2 [2] cf d0 [2] 88 c1 [2] c6 cd [2] ca c7 [2] dd cc [2] c6 82 [2] fb }

  condition:
    any of them
}