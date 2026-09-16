rule TTP_XOR_MULT_DOSStub_969f {
  strings:
    $key_969f = { c2 f7 [2] b6 ef [2] f1 ed [2] b6 fc [2] f8 f0 [2] f4 fa [2] e3 f1 [2] f8 bf [2] c5 }

  condition:
    any of them
}