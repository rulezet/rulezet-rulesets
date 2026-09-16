rule TTP_XOR_MULT_DOSStub_fcb8 {
  strings:
    $key_fcb8 = { a8 d0 [2] dc c8 [2] 9b ca [2] dc db [2] 92 d7 [2] 9e dd [2] 89 d6 [2] 92 98 [2] af }

  condition:
    any of them
}