rule TTP_XOR_MULT_DOSStub_6880 {
  strings:
    $key_6880 = { 3c e8 [2] 48 f0 [2] 0f f2 [2] 48 e3 [2] 06 ef [2] 0a e5 [2] 1d ee [2] 06 a0 [2] 3b }

  condition:
    any of them
}