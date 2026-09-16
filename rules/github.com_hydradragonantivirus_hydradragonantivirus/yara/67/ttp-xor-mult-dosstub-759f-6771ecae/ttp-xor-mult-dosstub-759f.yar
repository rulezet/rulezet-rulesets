rule TTP_XOR_MULT_DOSStub_759f {
  strings:
    $key_759f = { 21 f7 [2] 55 ef [2] 12 ed [2] 55 fc [2] 1b f0 [2] 17 fa [2] 00 f1 [2] 1b bf [2] 26 }

  condition:
    any of them
}