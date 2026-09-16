rule TTP_XOR_MULT_DOSStub_bebe {
  strings:
    $key_bebe = { ea d6 [2] 9e ce [2] d9 cc [2] 9e dd [2] d0 d1 [2] dc db [2] cb d0 [2] d0 9e [2] ed }

  condition:
    any of them
}