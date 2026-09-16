rule TTP_XOR_MULT_DOSStub_259f {
  strings:
    $key_259f = { 71 f7 [2] 05 ef [2] 42 ed [2] 05 fc [2] 4b f0 [2] 47 fa [2] 50 f1 [2] 4b bf [2] 76 }

  condition:
    any of them
}