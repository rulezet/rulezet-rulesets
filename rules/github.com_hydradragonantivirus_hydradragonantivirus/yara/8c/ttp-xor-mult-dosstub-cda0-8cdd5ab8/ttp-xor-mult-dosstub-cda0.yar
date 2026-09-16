rule TTP_XOR_MULT_DOSStub_cda0 {
  strings:
    $key_cda0 = { 99 c8 [2] ed d0 [2] aa d2 [2] ed c3 [2] a3 cf [2] af c5 [2] b8 ce [2] a3 80 [2] 9e }

  condition:
    any of them
}