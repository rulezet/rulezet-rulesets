rule TTP_XOR_MULT_DOSStub_bec8 {
  strings:
    $key_bec8 = { ea a0 [2] 9e b8 [2] d9 ba [2] 9e ab [2] d0 a7 [2] dc ad [2] cb a6 [2] d0 e8 [2] ed }

  condition:
    any of them
}