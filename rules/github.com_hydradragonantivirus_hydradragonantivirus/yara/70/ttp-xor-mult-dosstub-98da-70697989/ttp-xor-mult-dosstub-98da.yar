rule TTP_XOR_MULT_DOSStub_98da {
  strings:
    $key_98da = { cc b2 [2] b8 aa [2] ff a8 [2] b8 b9 [2] f6 b5 [2] fa bf [2] ed b4 [2] f6 fa [2] cb }

  condition:
    any of them
}