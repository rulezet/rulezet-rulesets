rule TTP_XOR_MULT_DOSStub_7f9f {
  strings:
    $key_7f9f = { 2b f7 [2] 5f ef [2] 18 ed [2] 5f fc [2] 11 f0 [2] 1d fa [2] 0a f1 [2] 11 bf [2] 2c }

  condition:
    any of them
}