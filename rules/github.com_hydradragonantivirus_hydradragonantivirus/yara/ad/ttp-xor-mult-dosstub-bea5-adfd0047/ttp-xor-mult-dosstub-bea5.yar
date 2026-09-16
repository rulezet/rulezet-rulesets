rule TTP_XOR_MULT_DOSStub_bea5 {
  strings:
    $key_bea5 = { ea cd [2] 9e d5 [2] d9 d7 [2] 9e c6 [2] d0 ca [2] dc c0 [2] cb cb [2] d0 85 [2] ed }

  condition:
    any of them
}