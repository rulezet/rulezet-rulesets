rule TTP_XOR_MULT_DOSStub_8ebe {
  strings:
    $key_8ebe = { da d6 [2] ae ce [2] e9 cc [2] ae dd [2] e0 d1 [2] ec db [2] fb d0 [2] e0 9e [2] dd }

  condition:
    any of them
}