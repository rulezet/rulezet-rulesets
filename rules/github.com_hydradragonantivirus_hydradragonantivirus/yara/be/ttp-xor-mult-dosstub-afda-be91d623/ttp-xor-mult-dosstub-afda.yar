rule TTP_XOR_MULT_DOSStub_afda {
  strings:
    $key_afda = { fb b2 [2] 8f aa [2] c8 a8 [2] 8f b9 [2] c1 b5 [2] cd bf [2] da b4 [2] c1 fa [2] fc }

  condition:
    any of them
}