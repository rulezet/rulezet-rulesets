rule TTP_XOR_MULT_DOSStub_6f93 {
  strings:
    $key_6f93 = { 3b fb [2] 4f e3 [2] 08 e1 [2] 4f f0 [2] 01 fc [2] 0d f6 [2] 1a fd [2] 01 b3 [2] 3c }

  condition:
    any of them
}