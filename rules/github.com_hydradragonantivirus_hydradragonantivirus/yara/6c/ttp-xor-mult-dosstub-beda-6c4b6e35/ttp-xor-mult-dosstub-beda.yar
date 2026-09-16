rule TTP_XOR_MULT_DOSStub_beda {
  strings:
    $key_beda = { ea b2 [2] 9e aa [2] d9 a8 [2] 9e b9 [2] d0 b5 [2] dc bf [2] cb b4 [2] d0 fa [2] ed }

  condition:
    any of them
}