rule TTP_XOR_MULT_DOSStub_bebc {
  strings:
    $key_bebc = { ea d4 [2] 9e cc [2] d9 ce [2] 9e df [2] d0 d3 [2] dc d9 [2] cb d2 [2] d0 9c [2] ed }

  condition:
    any of them
}