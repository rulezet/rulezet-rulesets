rule TTP_XOR_MULT_DOSStub_d58c {
  strings:
    $key_d58c = { 81 e4 [2] f5 fc [2] b2 fe [2] f5 ef [2] bb e3 [2] b7 e9 [2] a0 e2 [2] bb ac [2] 86 }

  condition:
    any of them
}