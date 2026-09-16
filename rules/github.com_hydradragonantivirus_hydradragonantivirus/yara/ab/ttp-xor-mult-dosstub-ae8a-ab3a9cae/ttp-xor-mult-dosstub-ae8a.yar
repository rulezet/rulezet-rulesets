rule TTP_XOR_MULT_DOSStub_ae8a {
  strings:
    $key_ae8a = { fa e2 [2] 8e fa [2] c9 f8 [2] 8e e9 [2] c0 e5 [2] cc ef [2] db e4 [2] c0 aa [2] fd }

  condition:
    any of them
}