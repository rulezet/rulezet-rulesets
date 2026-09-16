rule TTP_XOR_MULT_DOSStub_d6cd {
  strings:
    $key_d6cd = { 82 a5 [2] f6 bd [2] b1 bf [2] f6 ae [2] b8 a2 [2] b4 a8 [2] a3 a3 [2] b8 ed [2] 85 }

  condition:
    any of them
}