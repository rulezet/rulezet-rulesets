rule TTP_XOR_MULT_DOSStub_be7b {
  strings:
    $key_be7b = { ea 13 [2] 9e 0b [2] d9 09 [2] 9e 18 [2] d0 14 [2] dc 1e [2] cb 15 [2] d0 5b [2] ed }

  condition:
    any of them
}