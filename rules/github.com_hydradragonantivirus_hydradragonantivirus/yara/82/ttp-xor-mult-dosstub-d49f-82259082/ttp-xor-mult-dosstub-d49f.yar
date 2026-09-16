rule TTP_XOR_MULT_DOSStub_d49f {
  strings:
    $key_d49f = { 80 f7 [2] f4 ef [2] b3 ed [2] f4 fc [2] ba f0 [2] b6 fa [2] a1 f1 [2] ba bf [2] 87 }

  condition:
    any of them
}