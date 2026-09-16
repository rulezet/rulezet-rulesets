rule TTP_XOR_MULT_DOSStub_be0d {
  strings:
    $key_be0d = { ea 65 [2] 9e 7d [2] d9 7f [2] 9e 6e [2] d0 62 [2] dc 68 [2] cb 63 [2] d0 2d [2] ed }

  condition:
    any of them
}