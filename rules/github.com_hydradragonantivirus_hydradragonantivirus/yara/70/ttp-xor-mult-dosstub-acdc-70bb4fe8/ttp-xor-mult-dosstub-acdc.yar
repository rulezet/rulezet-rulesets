rule TTP_XOR_MULT_DOSStub_acdc {
  strings:
    $key_acdc = { f8 b4 [2] 8c ac [2] cb ae [2] 8c bf [2] c2 b3 [2] ce b9 [2] d9 b2 [2] c2 fc [2] ff }

  condition:
    any of them
}