rule TTP_XOR_MULT_DOSStub_be4b {
  strings:
    $key_be4b = { ea 23 [2] 9e 3b [2] d9 39 [2] 9e 28 [2] d0 24 [2] dc 2e [2] cb 25 [2] d0 6b [2] ed }

  condition:
    any of them
}