rule TTP_XOR_MULT_DOSStub_3b93 {
  strings:
    $key_3b93 = { 6f fb [2] 1b e3 [2] 5c e1 [2] 1b f0 [2] 55 fc [2] 59 f6 [2] 4e fd [2] 55 b3 [2] 68 }

  condition:
    any of them
}