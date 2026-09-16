rule TTP_XOR_MULT_DOSStub_4d9f {
  strings:
    $key_4d9f = { 19 f7 [2] 6d ef [2] 2a ed [2] 6d fc [2] 23 f0 [2] 2f fa [2] 38 f1 [2] 23 bf [2] 1e }

  condition:
    any of them
}