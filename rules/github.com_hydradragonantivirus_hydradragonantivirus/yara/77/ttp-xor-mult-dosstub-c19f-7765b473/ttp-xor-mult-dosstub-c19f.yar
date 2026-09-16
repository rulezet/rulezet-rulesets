rule TTP_XOR_MULT_DOSStub_c19f {
  strings:
    $key_c19f = { 95 f7 [2] e1 ef [2] a6 ed [2] e1 fc [2] af f0 [2] a3 fa [2] b4 f1 [2] af bf [2] 92 }

  condition:
    any of them
}