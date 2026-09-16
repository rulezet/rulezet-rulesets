rule TTP_XOR_MULT_DOSStub_6d9f {
  strings:
    $key_6d9f = { 39 f7 [2] 4d ef [2] 0a ed [2] 4d fc [2] 03 f0 [2] 0f fa [2] 18 f1 [2] 03 bf [2] 3e }

  condition:
    any of them
}