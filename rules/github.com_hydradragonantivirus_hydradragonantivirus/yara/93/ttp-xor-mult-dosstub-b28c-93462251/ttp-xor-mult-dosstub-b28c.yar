rule TTP_XOR_MULT_DOSStub_b28c {
  strings:
    $key_b28c = { e6 e4 [2] 92 fc [2] d5 fe [2] 92 ef [2] dc e3 [2] d0 e9 [2] c7 e2 [2] dc ac [2] e1 }

  condition:
    any of them
}