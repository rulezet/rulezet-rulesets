rule TTP_XOR_MULT_DOSStub_be98 {
  strings:
    $key_be98 = { ea f0 [2] 9e e8 [2] d9 ea [2] 9e fb [2] d0 f7 [2] dc fd [2] cb f6 [2] d0 b8 [2] ed }

  condition:
    any of them
}