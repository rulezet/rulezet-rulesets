rule TTP_XOR_MULT_DOSStub_bece {
  strings:
    $key_bece = { ea a6 [2] 9e be [2] d9 bc [2] 9e ad [2] d0 a1 [2] dc ab [2] cb a0 [2] d0 ee [2] ed }

  condition:
    any of them
}