rule TTP_XOR_MULT_DOSStub_ebeb {
  strings:
    $key_ebeb = { bf 83 [2] cb 9b [2] 8c 99 [2] cb 88 [2] 85 84 [2] 89 8e [2] 9e 85 [2] 85 cb [2] b8 }

  condition:
    any of them
}