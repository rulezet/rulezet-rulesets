rule TTP_XOR_MULT_DOSStub_aebe {
  strings:
    $key_aebe = { fa d6 [2] 8e ce [2] c9 cc [2] 8e dd [2] c0 d1 [2] cc db [2] db d0 [2] c0 9e [2] fd }

  condition:
    any of them
}