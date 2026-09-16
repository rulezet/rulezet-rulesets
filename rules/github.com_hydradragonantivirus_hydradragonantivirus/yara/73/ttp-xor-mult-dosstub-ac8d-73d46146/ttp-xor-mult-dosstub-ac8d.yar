rule TTP_XOR_MULT_DOSStub_ac8d {
  strings:
    $key_ac8d = { f8 e5 [2] 8c fd [2] cb ff [2] 8c ee [2] c2 e2 [2] ce e8 [2] d9 e3 [2] c2 ad [2] ff }

  condition:
    any of them
}