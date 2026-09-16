rule TTP_XOR_MULT_DOSStub_d78c {
  strings:
    $key_d78c = { 83 e4 [2] f7 fc [2] b0 fe [2] f7 ef [2] b9 e3 [2] b5 e9 [2] a2 e2 [2] b9 ac [2] 84 }

  condition:
    any of them
}