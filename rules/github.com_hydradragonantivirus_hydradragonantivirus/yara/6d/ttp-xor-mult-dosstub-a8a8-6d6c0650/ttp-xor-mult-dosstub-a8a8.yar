rule TTP_XOR_MULT_DOSStub_a8a8 {
  strings:
    $key_a8a8 = { fc c0 [2] 88 d8 [2] cf da [2] 88 cb [2] c6 c7 [2] ca cd [2] dd c6 [2] c6 88 [2] fb }

  condition:
    any of them
}