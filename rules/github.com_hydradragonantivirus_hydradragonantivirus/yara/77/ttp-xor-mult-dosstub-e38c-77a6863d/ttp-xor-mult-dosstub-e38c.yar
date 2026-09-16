rule TTP_XOR_MULT_DOSStub_e38c {
  strings:
    $key_e38c = { b7 e4 [2] c3 fc [2] 84 fe [2] c3 ef [2] 8d e3 [2] 81 e9 [2] 96 e2 [2] 8d ac [2] b0 }

  condition:
    any of them
}