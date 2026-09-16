rule TTP_XOR_MULT_DOSStub_e48c {
  strings:
    $key_e48c = { b0 e4 [2] c4 fc [2] 83 fe [2] c4 ef [2] 8a e3 [2] 86 e9 [2] 91 e2 [2] 8a ac [2] b7 }

  condition:
    any of them
}