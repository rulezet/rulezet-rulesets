rule TTP_XOR_MULT_DOSStub_1afa {
  strings:
    $key_1afa = { 4e 92 [2] 3a 8a [2] 7d 88 [2] 3a 99 [2] 74 95 [2] 78 9f [2] 6f 94 [2] 74 da [2] 49 }

  condition:
    any of them
}