rule TTP_XOR_MULT_DOSStub_ddce {
  strings:
    $key_ddce = { 89 a6 [2] fd be [2] ba bc [2] fd ad [2] b3 a1 [2] bf ab [2] a8 a0 [2] b3 ee [2] 8e }

  condition:
    any of them
}