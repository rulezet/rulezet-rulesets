rule TTP_XOR_MULT_DOSStub_be1b {
  strings:
    $key_be1b = { ea 73 [2] 9e 6b [2] d9 69 [2] 9e 78 [2] d0 74 [2] dc 7e [2] cb 75 [2] d0 3b [2] ed }

  condition:
    any of them
}