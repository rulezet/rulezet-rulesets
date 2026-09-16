rule TTP_XOR_MULT_DOSStub_ebaf {
  strings:
    $key_ebaf = { bf c7 [2] cb df [2] 8c dd [2] cb cc [2] 85 c0 [2] 89 ca [2] 9e c1 [2] 85 8f [2] b8 }

  condition:
    any of them
}