rule TTP_XOR_MULT_DOSStub_be07 {
  strings:
    $key_be07 = { ea 6f [2] 9e 77 [2] d9 75 [2] 9e 64 [2] d0 68 [2] dc 62 [2] cb 69 [2] d0 27 [2] ed }

  condition:
    any of them
}