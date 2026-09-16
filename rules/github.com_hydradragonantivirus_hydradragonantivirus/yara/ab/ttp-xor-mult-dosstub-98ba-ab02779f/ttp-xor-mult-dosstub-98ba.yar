rule TTP_XOR_MULT_DOSStub_98ba {
  strings:
    $key_98ba = { cc d2 [2] b8 ca [2] ff c8 [2] b8 d9 [2] f6 d5 [2] fa df [2] ed d4 [2] f6 9a [2] cb }

  condition:
    any of them
}