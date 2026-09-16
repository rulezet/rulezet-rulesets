rule TTP_XOR_MULT_DOSStub_949f {
  strings:
    $key_949f = { c0 f7 [2] b4 ef [2] f3 ed [2] b4 fc [2] fa f0 [2] f6 fa [2] e1 f1 [2] fa bf [2] c7 }

  condition:
    any of them
}