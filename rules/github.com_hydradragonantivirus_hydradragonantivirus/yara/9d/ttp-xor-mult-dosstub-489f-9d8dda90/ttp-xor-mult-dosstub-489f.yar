rule TTP_XOR_MULT_DOSStub_489f {
  strings:
    $key_489f = { 1c f7 [2] 68 ef [2] 2f ed [2] 68 fc [2] 26 f0 [2] 2a fa [2] 3d f1 [2] 26 bf [2] 1b }

  condition:
    any of them
}