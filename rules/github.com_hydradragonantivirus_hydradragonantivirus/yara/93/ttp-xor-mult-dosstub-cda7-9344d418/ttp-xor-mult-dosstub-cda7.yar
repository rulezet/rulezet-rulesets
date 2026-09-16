rule TTP_XOR_MULT_DOSStub_cda7 {
  strings:
    $key_cda7 = { 99 cf [2] ed d7 [2] aa d5 [2] ed c4 [2] a3 c8 [2] af c2 [2] b8 c9 [2] a3 87 [2] 9e }

  condition:
    any of them
}