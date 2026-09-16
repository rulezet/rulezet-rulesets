rule TTP_XOR_MULT_DOSStub_be73 {
  strings:
    $key_be73 = { ea 1b [2] 9e 03 [2] d9 01 [2] 9e 10 [2] d0 1c [2] dc 16 [2] cb 1d [2] d0 53 [2] ed }

  condition:
    any of them
}