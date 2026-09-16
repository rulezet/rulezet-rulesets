rule TTP_XOR_MULT_DOSStub_2b93 {
  strings:
    $key_2b93 = { 7f fb [2] 0b e3 [2] 4c e1 [2] 0b f0 [2] 45 fc [2] 49 f6 [2] 5e fd [2] 45 b3 [2] 78 }

  condition:
    any of them
}