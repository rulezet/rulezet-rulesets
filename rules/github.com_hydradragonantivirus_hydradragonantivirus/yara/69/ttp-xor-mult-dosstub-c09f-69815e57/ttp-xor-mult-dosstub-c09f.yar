rule TTP_XOR_MULT_DOSStub_c09f {
  strings:
    $key_c09f = { 94 f7 [2] e0 ef [2] a7 ed [2] e0 fc [2] ae f0 [2] a2 fa [2] b5 f1 [2] ae bf [2] 93 }

  condition:
    any of them
}