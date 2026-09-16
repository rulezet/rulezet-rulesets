rule TTP_XOR_MULT_DOSStub_ac9e {
  strings:
    $key_ac9e = { f8 f6 [2] 8c ee [2] cb ec [2] 8c fd [2] c2 f1 [2] ce fb [2] d9 f0 [2] c2 be [2] ff }

  condition:
    any of them
}