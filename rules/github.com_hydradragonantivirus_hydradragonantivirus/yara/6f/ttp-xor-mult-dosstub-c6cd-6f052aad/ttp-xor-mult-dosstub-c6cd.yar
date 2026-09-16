rule TTP_XOR_MULT_DOSStub_c6cd {
  strings:
    $key_c6cd = { 92 a5 [2] e6 bd [2] a1 bf [2] e6 ae [2] a8 a2 [2] a4 a8 [2] b3 a3 [2] a8 ed [2] 95 }

  condition:
    any of them
}