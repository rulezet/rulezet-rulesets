rule TTP_XOR_MULT_DOSStub_f68a {
  strings:
    $key_f68a = { a2 e2 [2] d6 fa [2] 91 f8 [2] d6 e9 [2] 98 e5 [2] 94 ef [2] 83 e4 [2] 98 aa [2] a5 }

  condition:
    any of them
}