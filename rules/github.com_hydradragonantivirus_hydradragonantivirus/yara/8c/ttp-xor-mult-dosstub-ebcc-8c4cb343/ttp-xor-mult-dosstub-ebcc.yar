rule TTP_XOR_MULT_DOSStub_ebcc {
  strings:
    $key_ebcc = { bf a4 [2] cb bc [2] 8c be [2] cb af [2] 85 a3 [2] 89 a9 [2] 9e a2 [2] 85 ec [2] b8 }

  condition:
    any of them
}