rule TTP_XOR_MULT_DOSStub_be94 {
  strings:
    $key_be94 = { ea fc [2] 9e e4 [2] d9 e6 [2] 9e f7 [2] d0 fb [2] dc f1 [2] cb fa [2] d0 b4 [2] ed }

  condition:
    any of them
}