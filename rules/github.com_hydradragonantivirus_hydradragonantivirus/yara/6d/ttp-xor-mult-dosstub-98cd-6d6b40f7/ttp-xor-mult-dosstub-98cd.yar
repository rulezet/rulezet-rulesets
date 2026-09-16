rule TTP_XOR_MULT_DOSStub_98cd {
  strings:
    $key_98cd = { cc a5 [2] b8 bd [2] ff bf [2] b8 ae [2] f6 a2 [2] fa a8 [2] ed a3 [2] f6 ed [2] cb }

  condition:
    any of them
}