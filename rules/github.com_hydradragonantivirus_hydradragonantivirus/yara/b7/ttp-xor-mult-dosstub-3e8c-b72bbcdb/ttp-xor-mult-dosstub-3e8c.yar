rule TTP_XOR_MULT_DOSStub_3e8c {
  strings:
    $key_3e8c = { 6a e4 [2] 1e fc [2] 59 fe [2] 1e ef [2] 50 e3 [2] 5c e9 [2] 4b e2 [2] 50 ac [2] 6d }

  condition:
    any of them
}