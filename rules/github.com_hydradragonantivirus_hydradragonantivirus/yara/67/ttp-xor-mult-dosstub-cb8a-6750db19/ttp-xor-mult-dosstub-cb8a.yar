rule TTP_XOR_MULT_DOSStub_cb8a {
  strings:
    $key_cb8a = { 9f e2 [2] eb fa [2] ac f8 [2] eb e9 [2] a5 e5 [2] a9 ef [2] be e4 [2] a5 aa [2] 98 }

  condition:
    any of them
}