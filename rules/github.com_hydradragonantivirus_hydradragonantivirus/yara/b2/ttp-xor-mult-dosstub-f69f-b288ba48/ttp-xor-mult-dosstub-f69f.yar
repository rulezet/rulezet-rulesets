rule TTP_XOR_MULT_DOSStub_f69f {
  strings:
    $key_f69f = { a2 f7 [2] d6 ef [2] 91 ed [2] d6 fc [2] 98 f0 [2] 94 fa [2] 83 f1 [2] 98 bf [2] a5 }

  condition:
    any of them
}