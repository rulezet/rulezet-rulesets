rule TTP_XOR_MULT_DOSStub_a9ba {
  strings:
    $key_a9ba = { fd d2 [2] 89 ca [2] ce c8 [2] 89 d9 [2] c7 d5 [2] cb df [2] dc d4 [2] c7 9a [2] fa }

  condition:
    any of them
}