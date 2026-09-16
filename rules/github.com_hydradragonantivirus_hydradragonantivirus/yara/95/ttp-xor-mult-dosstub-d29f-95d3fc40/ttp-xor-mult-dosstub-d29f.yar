rule TTP_XOR_MULT_DOSStub_d29f {
  strings:
    $key_d29f = { 86 f7 [2] f2 ef [2] b5 ed [2] f2 fc [2] bc f0 [2] b0 fa [2] a7 f1 [2] bc bf [2] 81 }

  condition:
    any of them
}