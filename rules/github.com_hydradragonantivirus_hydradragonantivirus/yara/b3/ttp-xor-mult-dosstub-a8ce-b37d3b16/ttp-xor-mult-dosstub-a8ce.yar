rule TTP_XOR_MULT_DOSStub_a8ce {
  strings:
    $key_a8ce = { fc a6 [2] 88 be [2] cf bc [2] 88 ad [2] c6 a1 [2] ca ab [2] dd a0 [2] c6 ee [2] fb }

  condition:
    any of them
}