rule TTP_XOR_MULT_DOSStub_beb8 {
  strings:
    $key_beb8 = { ea d0 [2] 9e c8 [2] d9 ca [2] 9e db [2] d0 d7 [2] dc dd [2] cb d6 [2] d0 98 [2] ed }

  condition:
    any of them
}