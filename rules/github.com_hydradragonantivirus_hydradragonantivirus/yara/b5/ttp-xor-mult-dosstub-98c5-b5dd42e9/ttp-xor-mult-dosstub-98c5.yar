rule TTP_XOR_MULT_DOSStub_98c5 {
  strings:
    $key_98c5 = { cc ad [2] b8 b5 [2] ff b7 [2] b8 a6 [2] f6 aa [2] fa a0 [2] ed ab [2] f6 e5 [2] cb }

  condition:
    any of them
}