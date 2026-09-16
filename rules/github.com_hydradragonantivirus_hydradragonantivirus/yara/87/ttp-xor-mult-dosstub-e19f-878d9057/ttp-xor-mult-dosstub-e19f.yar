rule TTP_XOR_MULT_DOSStub_e19f {
  strings:
    $key_e19f = { b5 f7 [2] c1 ef [2] 86 ed [2] c1 fc [2] 8f f0 [2] 83 fa [2] 94 f1 [2] 8f bf [2] b2 }

  condition:
    any of them
}