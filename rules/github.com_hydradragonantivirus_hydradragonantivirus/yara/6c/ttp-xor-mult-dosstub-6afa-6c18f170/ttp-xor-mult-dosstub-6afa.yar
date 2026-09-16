rule TTP_XOR_MULT_DOSStub_6afa {
  strings:
    $key_6afa = { 3e 92 [2] 4a 8a [2] 0d 88 [2] 4a 99 [2] 04 95 [2] 08 9f [2] 1f 94 [2] 04 da [2] 39 }

  condition:
    any of them
}