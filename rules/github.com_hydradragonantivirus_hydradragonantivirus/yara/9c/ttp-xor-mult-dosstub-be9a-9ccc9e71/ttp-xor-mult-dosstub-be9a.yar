rule TTP_XOR_MULT_DOSStub_be9a {
  strings:
    $key_be9a = { ea f2 [2] 9e ea [2] d9 e8 [2] 9e f9 [2] d0 f5 [2] dc ff [2] cb f4 [2] d0 ba [2] ed }

  condition:
    any of them
}