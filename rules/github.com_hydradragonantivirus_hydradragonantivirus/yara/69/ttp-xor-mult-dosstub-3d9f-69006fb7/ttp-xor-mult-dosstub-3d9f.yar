rule TTP_XOR_MULT_DOSStub_3d9f {
  strings:
    $key_3d9f = { 69 f7 [2] 1d ef [2] 5a ed [2] 1d fc [2] 53 f0 [2] 5f fa [2] 48 f1 [2] 53 bf [2] 6e }

  condition:
    any of them
}