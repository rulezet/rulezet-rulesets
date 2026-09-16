rule TTP_XOR_MULT_DOSStub_accc {
  strings:
    $key_accc = { f8 a4 [2] 8c bc [2] cb be [2] 8c af [2] c2 a3 [2] ce a9 [2] d9 a2 [2] c2 ec [2] ff }

  condition:
    any of them
}