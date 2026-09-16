rule TTP_XOR_MULT_DOSStub_a8a5 {
  strings:
    $key_a8a5 = { fc cd [2] 88 d5 [2] cf d7 [2] 88 c6 [2] c6 ca [2] ca c0 [2] dd cb [2] c6 85 [2] fb }

  condition:
    any of them
}