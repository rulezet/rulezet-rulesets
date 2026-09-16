rule TTP_XOR_MULT_DOSStub_d48c {
  strings:
    $key_d48c = { 80 e4 [2] f4 fc [2] b3 fe [2] f4 ef [2] ba e3 [2] b6 e9 [2] a1 e2 [2] ba ac [2] 87 }

  condition:
    any of them
}