rule TTP_XOR_MULT_DOSStub_fb8a {
  strings:
    $key_fb8a = { af e2 [2] db fa [2] 9c f8 [2] db e9 [2] 95 e5 [2] 99 ef [2] 8e e4 [2] 95 aa [2] a8 }

  condition:
    any of them
}