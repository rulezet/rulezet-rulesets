rule TTP_XOR_MULT_DOSStub_98af {
  strings:
    $key_98af = { cc c7 [2] b8 df [2] ff dd [2] b8 cc [2] f6 c0 [2] fa ca [2] ed c1 [2] f6 8f [2] cb }

  condition:
    any of them
}