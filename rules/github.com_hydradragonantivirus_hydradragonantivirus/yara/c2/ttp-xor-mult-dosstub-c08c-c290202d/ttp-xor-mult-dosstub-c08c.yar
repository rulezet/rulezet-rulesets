rule TTP_XOR_MULT_DOSStub_c08c {
  strings:
    $key_c08c = { 94 e4 [2] e0 fc [2] a7 fe [2] e0 ef [2] ae e3 [2] a2 e9 [2] b5 e2 [2] ae ac [2] 93 }

  condition:
    any of them
}