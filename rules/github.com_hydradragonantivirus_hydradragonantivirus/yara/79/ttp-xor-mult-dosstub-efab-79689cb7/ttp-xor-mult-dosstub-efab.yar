rule TTP_XOR_MULT_DOSStub_efab {
  strings:
    $key_efab = { bb c3 [2] cf db [2] 88 d9 [2] cf c8 [2] 81 c4 [2] 8d ce [2] 9a c5 [2] 81 8b [2] bc }

  condition:
    any of them
}