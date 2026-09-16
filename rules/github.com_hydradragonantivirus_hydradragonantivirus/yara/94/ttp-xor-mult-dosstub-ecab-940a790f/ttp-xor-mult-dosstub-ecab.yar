rule TTP_XOR_MULT_DOSStub_ecab {
  strings:
    $key_ecab = { b8 c3 [2] cc db [2] 8b d9 [2] cc c8 [2] 82 c4 [2] 8e ce [2] 99 c5 [2] 82 8b [2] bf }

  condition:
    any of them
}