rule TTP_XOR_MULT_DOSStub_afcb {
  strings:
    $key_afcb = { fb a3 [2] 8f bb [2] c8 b9 [2] 8f a8 [2] c1 a4 [2] cd ae [2] da a5 [2] c1 eb [2] fc }

  condition:
    any of them
}