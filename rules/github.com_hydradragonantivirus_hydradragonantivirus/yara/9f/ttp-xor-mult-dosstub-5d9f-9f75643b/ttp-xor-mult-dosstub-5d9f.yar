rule TTP_XOR_MULT_DOSStub_5d9f {
  strings:
    $key_5d9f = { 09 f7 [2] 7d ef [2] 3a ed [2] 7d fc [2] 33 f0 [2] 3f fa [2] 28 f1 [2] 33 bf [2] 0e }

  condition:
    any of them
}