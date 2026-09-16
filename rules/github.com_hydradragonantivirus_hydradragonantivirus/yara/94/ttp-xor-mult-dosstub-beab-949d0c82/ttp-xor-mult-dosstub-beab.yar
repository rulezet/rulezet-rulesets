rule TTP_XOR_MULT_DOSStub_beab {
  strings:
    $key_beab = { ea c3 [2] 9e db [2] d9 d9 [2] 9e c8 [2] d0 c4 [2] dc ce [2] cb c5 [2] d0 8b [2] ed }

  condition:
    any of them
}