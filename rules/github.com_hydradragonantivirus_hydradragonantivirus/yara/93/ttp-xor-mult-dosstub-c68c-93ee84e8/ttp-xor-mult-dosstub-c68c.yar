rule TTP_XOR_MULT_DOSStub_c68c {
  strings:
    $key_c68c = { 92 e4 [2] e6 fc [2] a1 fe [2] e6 ef [2] a8 e3 [2] a4 e9 [2] b3 e2 [2] a8 ac [2] 95 }

  condition:
    any of them
}