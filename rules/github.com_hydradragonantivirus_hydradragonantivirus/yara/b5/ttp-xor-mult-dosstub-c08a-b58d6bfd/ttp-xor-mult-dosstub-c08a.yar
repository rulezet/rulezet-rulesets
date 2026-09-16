rule TTP_XOR_MULT_DOSStub_c08a {
  strings:
    $key_c08a = { 94 e2 [2] e0 fa [2] a7 f8 [2] e0 e9 [2] ae e5 [2] a2 ef [2] b5 e4 [2] ae aa [2] 93 }

  condition:
    any of them
}