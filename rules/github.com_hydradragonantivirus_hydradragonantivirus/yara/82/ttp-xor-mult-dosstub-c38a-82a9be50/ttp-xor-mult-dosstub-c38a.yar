rule TTP_XOR_MULT_DOSStub_c38a {
  strings:
    $key_c38a = { 97 e2 [2] e3 fa [2] a4 f8 [2] e3 e9 [2] ad e5 [2] a1 ef [2] b6 e4 [2] ad aa [2] 90 }

  condition:
    any of them
}