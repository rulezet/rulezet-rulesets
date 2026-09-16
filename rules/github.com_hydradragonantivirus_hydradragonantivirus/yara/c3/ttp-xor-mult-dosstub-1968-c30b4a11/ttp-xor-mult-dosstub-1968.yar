rule TTP_XOR_MULT_DOSStub_1968 {
  strings:
    $key_1968 = { 4d 00 [2] 39 18 [2] 7e 1a [2] 39 0b [2] 77 07 [2] 7b 0d [2] 6c 06 [2] 77 48 [2] 4a }

  condition:
    any of them
}