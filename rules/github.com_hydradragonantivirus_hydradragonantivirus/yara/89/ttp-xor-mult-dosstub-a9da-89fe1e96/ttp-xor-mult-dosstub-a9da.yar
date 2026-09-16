rule TTP_XOR_MULT_DOSStub_a9da {
  strings:
    $key_a9da = { fd b2 [2] 89 aa [2] ce a8 [2] 89 b9 [2] c7 b5 [2] cb bf [2] dc b4 [2] c7 fa [2] fa }

  condition:
    any of them
}