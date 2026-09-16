rule TTP_XOR_MULT_DOSStub_beeb {
  strings:
    $key_beeb = { ea 83 [2] 9e 9b [2] d9 99 [2] 9e 88 [2] d0 84 [2] dc 8e [2] cb 85 [2] d0 cb [2] ed }

  condition:
    any of them
}