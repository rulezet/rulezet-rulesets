rule TTP_XOR_MULT_DOSStub_1f93 {
  strings:
    $key_1f93 = { 4b fb [2] 3f e3 [2] 78 e1 [2] 3f f0 [2] 71 fc [2] 7d f6 [2] 6a fd [2] 71 b3 [2] 4c }

  condition:
    any of them
}