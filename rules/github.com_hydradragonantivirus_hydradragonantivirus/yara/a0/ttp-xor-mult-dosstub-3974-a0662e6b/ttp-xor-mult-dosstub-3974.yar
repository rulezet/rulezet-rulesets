rule TTP_XOR_MULT_DOSStub_3974 {
  strings:
    $key_3974 = { 6d 1c [2] 19 04 [2] 5e 06 [2] 19 17 [2] 57 1b [2] 5b 11 [2] 4c 1a [2] 57 54 [2] 6a }

  condition:
    any of them
}