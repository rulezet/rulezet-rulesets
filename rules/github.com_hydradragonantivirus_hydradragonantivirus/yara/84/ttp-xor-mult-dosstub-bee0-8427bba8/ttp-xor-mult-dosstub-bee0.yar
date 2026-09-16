rule TTP_XOR_MULT_DOSStub_bee0 {
  strings:
    $key_bee0 = { ea 88 [2] 9e 90 [2] d9 92 [2] 9e 83 [2] d0 8f [2] dc 85 [2] cb 8e [2] d0 c0 [2] ed }

  condition:
    any of them
}