rule TTP_XOR_MULT_DOSStub_be0e {
  strings:
    $key_be0e = { ea 66 [2] 9e 7e [2] d9 7c [2] 9e 6d [2] d0 61 [2] dc 6b [2] cb 60 [2] d0 2e [2] ed }

  condition:
    any of them
}