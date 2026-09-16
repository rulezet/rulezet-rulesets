rule TTP_XOR_MULT_DOSStub_be71 {
  strings:
    $key_be71 = { ea 19 [2] 9e 01 [2] d9 03 [2] 9e 12 [2] d0 1e [2] dc 14 [2] cb 1f [2] d0 51 [2] ed }

  condition:
    any of them
}