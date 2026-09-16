rule TTP_XOR_MULT_DOSStub_2e8c {
  strings:
    $key_2e8c = { 7a e4 [2] 0e fc [2] 49 fe [2] 0e ef [2] 40 e3 [2] 4c e9 [2] 5b e2 [2] 40 ac [2] 7d }

  condition:
    any of them
}