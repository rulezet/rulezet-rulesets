rule TTP_XOR_MULT_DOSStub_a9af {
  strings:
    $key_a9af = { fd c7 [2] 89 df [2] ce dd [2] 89 cc [2] c7 c0 [2] cb ca [2] dc c1 [2] c7 8f [2] fa }

  condition:
    any of them
}