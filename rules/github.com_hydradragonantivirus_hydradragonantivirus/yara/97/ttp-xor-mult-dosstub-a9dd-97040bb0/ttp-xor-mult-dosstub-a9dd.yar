rule TTP_XOR_MULT_DOSStub_a9dd {
  strings:
    $key_a9dd = { fd b5 [2] 89 ad [2] ce af [2] 89 be [2] c7 b2 [2] cb b8 [2] dc b3 [2] c7 fd [2] fa }

  condition:
    any of them
}