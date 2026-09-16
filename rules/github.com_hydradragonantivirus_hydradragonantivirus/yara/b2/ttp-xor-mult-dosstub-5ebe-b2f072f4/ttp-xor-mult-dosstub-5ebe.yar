rule TTP_XOR_MULT_DOSStub_5ebe {
  strings:
    $key_5ebe = { 0a d6 [2] 7e ce [2] 39 cc [2] 7e dd [2] 30 d1 [2] 3c db [2] 2b d0 [2] 30 9e [2] 0d }

  condition:
    any of them
}