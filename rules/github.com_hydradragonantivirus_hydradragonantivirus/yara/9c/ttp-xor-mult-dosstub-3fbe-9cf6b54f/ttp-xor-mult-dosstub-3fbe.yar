rule TTP_XOR_MULT_DOSStub_3fbe {
  strings:
    $key_3fbe = { 6b d6 [2] 1f ce [2] 58 cc [2] 1f dd [2] 51 d1 [2] 5d db [2] 4a d0 [2] 51 9e [2] 6c }

  condition:
    any of them
}