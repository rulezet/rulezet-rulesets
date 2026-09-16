rule TTP_XOR_MULT_DOSStub_7f93 {
  strings:
    $key_7f93 = { 2b fb [2] 5f e3 [2] 18 e1 [2] 5f f0 [2] 11 fc [2] 1d f6 [2] 0a fd [2] 11 b3 [2] 2c }

  condition:
    any of them
}