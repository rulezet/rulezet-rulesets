rule TTP_XOR_MULT_DOSStub_c29f {
  strings:
    $key_c29f = { 96 f7 [2] e2 ef [2] a5 ed [2] e2 fc [2] ac f0 [2] a0 fa [2] b7 f1 [2] ac bf [2] 91 }

  condition:
    any of them
}