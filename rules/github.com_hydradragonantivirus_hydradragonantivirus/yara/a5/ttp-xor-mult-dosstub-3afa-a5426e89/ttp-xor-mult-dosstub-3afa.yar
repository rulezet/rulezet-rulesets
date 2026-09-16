rule TTP_XOR_MULT_DOSStub_3afa {
  strings:
    $key_3afa = { 6e 92 [2] 1a 8a [2] 5d 88 [2] 1a 99 [2] 54 95 [2] 58 9f [2] 4f 94 [2] 54 da [2] 69 }

  condition:
    any of them
}