rule TTP_XOR_MULT_DOSStub_2d9f {
  strings:
    $key_2d9f = { 79 f7 [2] 0d ef [2] 4a ed [2] 0d fc [2] 43 f0 [2] 4f fa [2] 58 f1 [2] 43 bf [2] 7e }

  condition:
    any of them
}