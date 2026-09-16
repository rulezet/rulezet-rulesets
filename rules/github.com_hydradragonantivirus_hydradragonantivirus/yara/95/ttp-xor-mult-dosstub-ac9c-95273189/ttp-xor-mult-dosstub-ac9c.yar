rule TTP_XOR_MULT_DOSStub_ac9c {
  strings:
    $key_ac9c = { f8 f4 [2] 8c ec [2] cb ee [2] 8c ff [2] c2 f3 [2] ce f9 [2] d9 f2 [2] c2 bc [2] ff }

  condition:
    any of them
}