rule TTP_XOR_MULT_DOSStub_bbdd {
  strings:
    $key_bbdd = { ef b5 [2] 9b ad [2] dc af [2] 9b be [2] d5 b2 [2] d9 b8 [2] ce b3 [2] d5 fd [2] e8 }

  condition:
    any of them
}