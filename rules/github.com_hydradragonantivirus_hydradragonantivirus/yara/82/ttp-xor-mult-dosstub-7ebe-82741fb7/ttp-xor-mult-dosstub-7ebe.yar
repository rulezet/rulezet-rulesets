rule TTP_XOR_MULT_DOSStub_7ebe {
  strings:
    $key_7ebe = { 2a d6 [2] 5e ce [2] 19 cc [2] 5e dd [2] 10 d1 [2] 1c db [2] 0b d0 [2] 10 9e [2] 2d }

  condition:
    any of them
}