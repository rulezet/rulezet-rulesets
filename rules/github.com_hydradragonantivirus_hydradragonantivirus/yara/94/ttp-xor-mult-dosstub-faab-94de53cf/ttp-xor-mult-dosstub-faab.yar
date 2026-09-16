rule TTP_XOR_MULT_DOSStub_faab {
  strings:
    $key_faab = { ae c3 [2] da db [2] 9d d9 [2] da c8 [2] 94 c4 [2] 98 ce [2] 8f c5 [2] 94 8b [2] a9 }

  condition:
    any of them
}