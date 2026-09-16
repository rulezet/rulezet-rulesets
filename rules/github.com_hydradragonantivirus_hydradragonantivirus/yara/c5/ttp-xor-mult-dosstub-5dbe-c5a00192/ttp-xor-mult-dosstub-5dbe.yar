rule TTP_XOR_MULT_DOSStub_5dbe {
  strings:
    $key_5dbe = { 09 d6 [2] 7d ce [2] 3a cc [2] 7d dd [2] 33 d1 [2] 3f db [2] 28 d0 [2] 33 9e [2] 0e }

  condition:
    any of them
}