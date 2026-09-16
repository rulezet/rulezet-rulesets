rule TTP_XOR_MULT_DOSStub_d9d2 {
  strings:
    $key_d9d2 = { 8d ba [2] f9 a2 [2] be a0 [2] f9 b1 [2] b7 bd [2] bb b7 [2] ac bc [2] b7 f2 [2] 8a }

  condition:
    any of them
}