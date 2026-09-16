rule TTP_XOR_MULT_DOSStub_bec6 {
  strings:
    $key_bec6 = { ea ae [2] 9e b6 [2] d9 b4 [2] 9e a5 [2] d0 a9 [2] dc a3 [2] cb a8 [2] d0 e6 [2] ed }

  condition:
    any of them
}