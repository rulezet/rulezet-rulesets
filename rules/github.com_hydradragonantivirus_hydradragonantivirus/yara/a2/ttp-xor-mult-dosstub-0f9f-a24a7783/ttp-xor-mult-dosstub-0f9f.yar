rule TTP_XOR_MULT_DOSStub_0f9f {
  strings:
    $key_0f9f = { 5b f7 [2] 2f ef [2] 68 ed [2] 2f fc [2] 61 f0 [2] 6d fa [2] 7a f1 [2] 61 bf [2] 5c }

  condition:
    any of them
}