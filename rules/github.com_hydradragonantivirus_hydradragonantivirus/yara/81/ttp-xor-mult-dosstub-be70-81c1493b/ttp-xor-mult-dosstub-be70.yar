rule TTP_XOR_MULT_DOSStub_be70 {
  strings:
    $key_be70 = { ea 18 [2] 9e 00 [2] d9 02 [2] 9e 13 [2] d0 1f [2] dc 15 [2] cb 1e [2] d0 50 [2] ed }

  condition:
    any of them
}