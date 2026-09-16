rule TTP_XOR_MULT_DOSStub_be64 {
  strings:
    $key_be64 = { ea 0c [2] 9e 14 [2] d9 16 [2] 9e 07 [2] d0 0b [2] dc 01 [2] cb 0a [2] d0 44 [2] ed }

  condition:
    any of them
}