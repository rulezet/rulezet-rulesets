rule TTP_XOR_MULT_DOSStub_768c {
  strings:
    $key_768c = { 22 e4 [2] 56 fc [2] 11 fe [2] 56 ef [2] 18 e3 [2] 14 e9 [2] 03 e2 [2] 18 ac [2] 25 }

  condition:
    any of them
}