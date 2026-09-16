rule TTP_XOR_MULT_DOSStub_4b93 {
  strings:
    $key_4b93 = { 1f fb [2] 6b e3 [2] 2c e1 [2] 6b f0 [2] 25 fc [2] 29 f6 [2] 3e fd [2] 25 b3 [2] 18 }

  condition:
    any of them
}