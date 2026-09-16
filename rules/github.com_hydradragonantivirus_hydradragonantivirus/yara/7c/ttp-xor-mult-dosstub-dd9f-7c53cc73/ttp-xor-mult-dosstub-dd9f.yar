rule TTP_XOR_MULT_DOSStub_dd9f {
  strings:
    $key_dd9f = { 89 f7 [2] fd ef [2] ba ed [2] fd fc [2] b3 f0 [2] bf fa [2] a8 f1 [2] b3 bf [2] 8e }

  condition:
    any of them
}