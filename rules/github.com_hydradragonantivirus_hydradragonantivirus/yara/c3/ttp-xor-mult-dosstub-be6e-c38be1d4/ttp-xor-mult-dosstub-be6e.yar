rule TTP_XOR_MULT_DOSStub_be6e {
  strings:
    $key_be6e = { ea 06 [2] 9e 1e [2] d9 1c [2] 9e 0d [2] d0 01 [2] dc 0b [2] cb 00 [2] d0 4e [2] ed }

  condition:
    any of them
}