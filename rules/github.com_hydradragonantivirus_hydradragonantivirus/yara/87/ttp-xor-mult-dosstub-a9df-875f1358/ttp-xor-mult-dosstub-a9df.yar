rule TTP_XOR_MULT_DOSStub_a9df {
  strings:
    $key_a9df = { fd b7 [2] 89 af [2] ce ad [2] 89 bc [2] c7 b0 [2] cb ba [2] dc b1 [2] c7 ff [2] fa }

  condition:
    any of them
}