rule TTP_XOR_MULT_DOSStub_6b93 {
  strings:
    $key_6b93 = { 3f fb [2] 4b e3 [2] 0c e1 [2] 4b f0 [2] 05 fc [2] 09 f6 [2] 1e fd [2] 05 b3 [2] 38 }

  condition:
    any of them
}