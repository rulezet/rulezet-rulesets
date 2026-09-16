rule TTP_XOR_MULT_DOSStub_e0cd {
  strings:
    $key_e0cd = { b4 a5 [2] c0 bd [2] 87 bf [2] c0 ae [2] 8e a2 [2] 82 a8 [2] 95 a3 [2] 8e ed [2] b3 }

  condition:
    any of them
}