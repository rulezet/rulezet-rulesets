rule TTP_XOR_MULT_DOSStub_e98c {
  strings:
    $key_e98c = { bd e4 [2] c9 fc [2] 8e fe [2] c9 ef [2] 87 e3 [2] 8b e9 [2] 9c e2 [2] 87 ac [2] ba }

  condition:
    any of them
}