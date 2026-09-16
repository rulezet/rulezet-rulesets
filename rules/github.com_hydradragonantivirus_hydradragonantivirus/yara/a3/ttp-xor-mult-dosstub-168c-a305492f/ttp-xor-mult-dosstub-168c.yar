rule TTP_XOR_MULT_DOSStub_168c {
  strings:
    $key_168c = { 42 e4 [2] 36 fc [2] 71 fe [2] 36 ef [2] 78 e3 [2] 74 e9 [2] 63 e2 [2] 78 ac [2] 45 }

  condition:
    any of them
}