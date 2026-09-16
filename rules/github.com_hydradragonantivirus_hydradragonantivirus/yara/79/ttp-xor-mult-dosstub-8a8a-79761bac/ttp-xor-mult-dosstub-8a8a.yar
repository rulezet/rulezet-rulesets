rule TTP_XOR_MULT_DOSStub_8a8a {
  strings:
    $key_8a8a = { de e2 [2] aa fa [2] ed f8 [2] aa e9 [2] e4 e5 [2] e8 ef [2] ff e4 [2] e4 aa [2] d9 }

  condition:
    any of them
}