rule TTP_XOR_MULT_DOSStub_c58c {
  strings:
    $key_c58c = { 91 e4 [2] e5 fc [2] a2 fe [2] e5 ef [2] ab e3 [2] a7 e9 [2] b0 e2 [2] ab ac [2] 96 }

  condition:
    any of them
}