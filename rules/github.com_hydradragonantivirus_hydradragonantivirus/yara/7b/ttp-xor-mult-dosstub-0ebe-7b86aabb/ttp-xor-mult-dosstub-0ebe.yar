rule TTP_XOR_MULT_DOSStub_0ebe {
  strings:
    $key_0ebe = { 5a d6 [2] 2e ce [2] 69 cc [2] 2e dd [2] 60 d1 [2] 6c db [2] 7b d0 [2] 60 9e [2] 5d }

  condition:
    any of them
}