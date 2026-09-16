rule TTP_XOR_MULT_DOSStub_1d9f {
  strings:
    $key_1d9f = { 49 f7 [2] 3d ef [2] 7a ed [2] 3d fc [2] 73 f0 [2] 7f fa [2] 68 f1 [2] 73 bf [2] 4e }

  condition:
    any of them
}