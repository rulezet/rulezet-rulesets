rule TTP_XOR_MULT_DOSStub_8e8c {
  strings:
    $key_8e8c = { da e4 [2] ae fc [2] e9 fe [2] ae ef [2] e0 e3 [2] ec e9 [2] fb e2 [2] e0 ac [2] dd }

  condition:
    any of them
}