rule TTP_XOR_MULT_DOSStub_fa9f {
  strings:
    $key_fa9f = { ae f7 [2] da ef [2] 9d ed [2] da fc [2] 94 f0 [2] 98 fa [2] 8f f1 [2] 94 bf [2] a9 }

  condition:
    any of them
}