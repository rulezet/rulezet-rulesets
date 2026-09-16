rule TTP_XOR_MULT_DOSStub_bef4 {
  strings:
    $key_bef4 = { ea 9c [2] 9e 84 [2] d9 86 [2] 9e 97 [2] d0 9b [2] dc 91 [2] cb 9a [2] d0 d4 [2] ed }

  condition:
    any of them
}