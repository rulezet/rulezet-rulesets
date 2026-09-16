rule TTP_XOR_MULT_DOSStub_559f {
  strings:
    $key_559f = { 01 f7 [2] 75 ef [2] 32 ed [2] 75 fc [2] 3b f0 [2] 37 fa [2] 20 f1 [2] 3b bf [2] 06 }

  condition:
    any of them
}