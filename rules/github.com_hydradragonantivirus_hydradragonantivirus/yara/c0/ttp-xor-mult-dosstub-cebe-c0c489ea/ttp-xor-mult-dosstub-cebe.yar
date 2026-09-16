rule TTP_XOR_MULT_DOSStub_cebe {
  strings:
    $key_cebe = { 9a d6 [2] ee ce [2] a9 cc [2] ee dd [2] a0 d1 [2] ac db [2] bb d0 [2] a0 9e [2] 9d }

  condition:
    any of them
}