rule TTP_XOR_MULT_DOSStub_ccbe {
  strings:
    $key_ccbe = { 98 d6 [2] ec ce [2] ab cc [2] ec dd [2] a2 d1 [2] ae db [2] b9 d0 [2] a2 9e [2] 9f }

  condition:
    any of them
}