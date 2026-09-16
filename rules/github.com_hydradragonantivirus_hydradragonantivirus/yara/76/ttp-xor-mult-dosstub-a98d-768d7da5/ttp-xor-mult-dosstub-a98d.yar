rule TTP_XOR_MULT_DOSStub_a98d {
  strings:
    $key_a98d = { fd e5 [2] 89 fd [2] ce ff [2] 89 ee [2] c7 e2 [2] cb e8 [2] dc e3 [2] c7 ad [2] fa }

  condition:
    any of them
}