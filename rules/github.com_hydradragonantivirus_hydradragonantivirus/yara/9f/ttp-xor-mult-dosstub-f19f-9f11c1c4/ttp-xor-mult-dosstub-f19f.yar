rule TTP_XOR_MULT_DOSStub_f19f {
  strings:
    $key_f19f = { a5 f7 [2] d1 ef [2] 96 ed [2] d1 fc [2] 9f f0 [2] 93 fa [2] 84 f1 [2] 9f bf [2] a2 }

  condition:
    any of them
}