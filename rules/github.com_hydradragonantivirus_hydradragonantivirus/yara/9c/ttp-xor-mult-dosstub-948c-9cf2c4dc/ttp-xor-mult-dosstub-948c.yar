rule TTP_XOR_MULT_DOSStub_948c {
  strings:
    $key_948c = { c0 e4 [2] b4 fc [2] f3 fe [2] b4 ef [2] fa e3 [2] f6 e9 [2] e1 e2 [2] fa ac [2] c7 }

  condition:
    any of them
}