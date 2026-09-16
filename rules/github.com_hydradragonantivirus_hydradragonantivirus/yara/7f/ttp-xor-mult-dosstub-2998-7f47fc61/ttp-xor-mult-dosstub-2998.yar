rule TTP_XOR_MULT_DOSStub_2998 {
  strings:
    $key_2998 = { 7d f0 [2] 09 e8 [2] 4e ea [2] 09 fb [2] 47 f7 [2] 4b fd [2] 5c f6 [2] 47 b8 [2] 7a }

  condition:
    any of them
}