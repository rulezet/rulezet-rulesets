rule TTP_XOR_MULT_DOSStub_e68c {
  strings:
    $key_e68c = { b2 e4 [2] c6 fc [2] 81 fe [2] c6 ef [2] 88 e3 [2] 84 e9 [2] 93 e2 [2] 88 ac [2] b5 }

  condition:
    any of them
}