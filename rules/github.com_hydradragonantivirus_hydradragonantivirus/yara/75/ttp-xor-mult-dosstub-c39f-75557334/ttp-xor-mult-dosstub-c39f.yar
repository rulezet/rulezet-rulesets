rule TTP_XOR_MULT_DOSStub_c39f {
  strings:
    $key_c39f = { 97 f7 [2] e3 ef [2] a4 ed [2] e3 fc [2] ad f0 [2] a1 fa [2] b6 f1 [2] ad bf [2] 90 }

  condition:
    any of them
}