rule TTP_XOR_MULT_DOSStub_accd {
  strings:
    $key_accd = { f8 a5 [2] 8c bd [2] cb bf [2] 8c ae [2] c2 a2 [2] ce a8 [2] d9 a3 [2] c2 ed [2] ff }

  condition:
    any of them
}