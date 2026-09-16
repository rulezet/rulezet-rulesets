rule TTP_XOR_MULT_DOSStub_e9cd {
  strings:
    $key_e9cd = { bd a5 [2] c9 bd [2] 8e bf [2] c9 ae [2] 87 a2 [2] 8b a8 [2] 9c a3 [2] 87 ed [2] ba }

  condition:
    any of them
}