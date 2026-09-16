rule TTP_XOR_MULT_DOSStub_f0cd {
  strings:
    $key_f0cd = { a4 a5 [2] d0 bd [2] 97 bf [2] d0 ae [2] 9e a2 [2] 92 a8 [2] 85 a3 [2] 9e ed [2] a3 }

  condition:
    any of them
}