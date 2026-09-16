rule TTP_XOR_MULT_DOSStub_d18c {
  strings:
    $key_d18c = { 85 e4 [2] f1 fc [2] b6 fe [2] f1 ef [2] bf e3 [2] b3 e9 [2] a4 e2 [2] bf ac [2] 82 }

  condition:
    any of them
}