rule TTP_XOR_MULT_DOSStub_6f9f {
  strings:
    $key_6f9f = { 3b f7 [2] 4f ef [2] 08 ed [2] 4f fc [2] 01 f0 [2] 0d fa [2] 1a f1 [2] 01 bf [2] 3c }

  condition:
    any of them
}