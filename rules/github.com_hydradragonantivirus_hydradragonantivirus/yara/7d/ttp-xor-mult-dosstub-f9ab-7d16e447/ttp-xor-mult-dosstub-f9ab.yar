rule TTP_XOR_MULT_DOSStub_f9ab {
  strings:
    $key_f9ab = { ad c3 [2] d9 db [2] 9e d9 [2] d9 c8 [2] 97 c4 [2] 9b ce [2] 8c c5 [2] 97 8b [2] aa }

  condition:
    any of them
}