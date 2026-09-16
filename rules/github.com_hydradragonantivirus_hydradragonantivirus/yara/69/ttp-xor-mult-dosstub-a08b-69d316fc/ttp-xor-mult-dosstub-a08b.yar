rule TTP_XOR_MULT_DOSStub_a08b {
  strings:
    $key_a08b = { f4 e3 [2] 80 fb [2] c7 f9 [2] 80 e8 [2] ce e4 [2] c2 ee [2] d5 e5 [2] ce ab [2] f3 }

  condition:
    any of them
}