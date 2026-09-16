rule TTP_XOR_MULT_DOSStub_3cbe {
  strings:
    $key_3cbe = { 68 d6 [2] 1c ce [2] 5b cc [2] 1c dd [2] 52 d1 [2] 5e db [2] 49 d0 [2] 52 9e [2] 6f }

  condition:
    any of them
}