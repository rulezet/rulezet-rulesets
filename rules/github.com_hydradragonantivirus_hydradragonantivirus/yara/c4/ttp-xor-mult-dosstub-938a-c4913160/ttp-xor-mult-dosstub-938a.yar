rule TTP_XOR_MULT_DOSStub_938a {
  strings:
    $key_938a = { c7 e2 [2] b3 fa [2] f4 f8 [2] b3 e9 [2] fd e5 [2] f1 ef [2] e6 e4 [2] fd aa [2] c0 }

  condition:
    any of them
}