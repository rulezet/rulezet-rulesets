rule TTP_XOR_MULT_DOSStub_bbba {
  strings:
    $key_bbba = { ef d2 [2] 9b ca [2] dc c8 [2] 9b d9 [2] d5 d5 [2] d9 df [2] ce d4 [2] d5 9a [2] e8 }

  condition:
    any of them
}