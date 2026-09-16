rule TTP_XOR_MULT_DOSStub_ae8c {
  strings:
    $key_ae8c = { fa e4 [2] 8e fc [2] c9 fe [2] 8e ef [2] c0 e3 [2] cc e9 [2] db e2 [2] c0 ac [2] fd }

  condition:
    any of them
}