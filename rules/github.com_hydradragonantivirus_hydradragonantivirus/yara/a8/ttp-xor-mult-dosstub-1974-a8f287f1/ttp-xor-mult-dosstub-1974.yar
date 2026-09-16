rule TTP_XOR_MULT_DOSStub_1974 {
  strings:
    $key_1974 = { 4d 1c [2] 39 04 [2] 7e 06 [2] 39 17 [2] 77 1b [2] 7b 11 [2] 6c 1a [2] 77 54 [2] 4a }

  condition:
    any of them
}