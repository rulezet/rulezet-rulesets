rule TTP_XOR_MULT_DOSStub_c0cd {
  strings:
    $key_c0cd = { 94 a5 [2] e0 bd [2] a7 bf [2] e0 ae [2] ae a2 [2] a2 a8 [2] b5 a3 [2] ae ed [2] 93 }

  condition:
    any of them
}