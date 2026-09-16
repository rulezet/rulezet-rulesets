rule TTP_XOR_MULT_DOSStub_5cbe {
  strings:
    $key_5cbe = { 08 d6 [2] 7c ce [2] 3b cc [2] 7c dd [2] 32 d1 [2] 3e db [2] 29 d0 [2] 32 9e [2] 0f }

  condition:
    any of them
}