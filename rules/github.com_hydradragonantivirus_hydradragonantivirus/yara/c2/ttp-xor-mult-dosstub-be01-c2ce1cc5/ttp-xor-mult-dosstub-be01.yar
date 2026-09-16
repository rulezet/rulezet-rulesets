rule TTP_XOR_MULT_DOSStub_be01 {
  strings:
    $key_be01 = { ea 69 [2] 9e 71 [2] d9 73 [2] 9e 62 [2] d0 6e [2] dc 64 [2] cb 6f [2] d0 21 [2] ed }

  condition:
    any of them
}