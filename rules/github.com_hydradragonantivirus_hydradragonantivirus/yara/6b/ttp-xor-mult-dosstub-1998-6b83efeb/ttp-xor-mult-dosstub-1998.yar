rule TTP_XOR_MULT_DOSStub_1998 {
  strings:
    $key_1998 = { 4d f0 [2] 39 e8 [2] 7e ea [2] 39 fb [2] 77 f7 [2] 7b fd [2] 6c f6 [2] 77 b8 [2] 4a }

  condition:
    any of them
}