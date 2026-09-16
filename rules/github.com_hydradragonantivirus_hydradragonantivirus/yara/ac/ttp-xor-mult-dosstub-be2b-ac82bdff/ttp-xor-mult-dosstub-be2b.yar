rule TTP_XOR_MULT_DOSStub_be2b {
  strings:
    $key_be2b = { ea 43 [2] 9e 5b [2] d9 59 [2] 9e 48 [2] d0 44 [2] dc 4e [2] cb 45 [2] d0 0b [2] ed }

  condition:
    any of them
}