rule TTP_XOR_MULT_DOSStub_c49f {
  strings:
    $key_c49f = { 90 f7 [2] e4 ef [2] a3 ed [2] e4 fc [2] aa f0 [2] a6 fa [2] b1 f1 [2] aa bf [2] 97 }

  condition:
    any of them
}