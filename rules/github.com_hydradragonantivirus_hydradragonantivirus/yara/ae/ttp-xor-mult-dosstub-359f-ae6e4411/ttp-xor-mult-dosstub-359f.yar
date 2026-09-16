rule TTP_XOR_MULT_DOSStub_359f {
  strings:
    $key_359f = { 61 f7 [2] 15 ef [2] 52 ed [2] 15 fc [2] 5b f0 [2] 57 fa [2] 40 f1 [2] 5b bf [2] 66 }

  condition:
    any of them
}