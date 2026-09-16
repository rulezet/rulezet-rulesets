rule TTP_XOR_MULT_DOSStub_f392 {
  strings:
    $key_f392 = { a7 fa [2] d3 e2 [2] 94 e0 [2] d3 f1 [2] 9d fd [2] 91 f7 [2] 86 fc [2] 9d b2 [2] a0 }

  condition:
    any of them
}