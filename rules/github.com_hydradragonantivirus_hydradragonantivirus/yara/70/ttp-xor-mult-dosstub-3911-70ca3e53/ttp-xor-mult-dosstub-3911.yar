rule TTP_XOR_MULT_DOSStub_3911 {
  strings:
    $key_3911 = { 6d 79 [2] 19 61 [2] 5e 63 [2] 19 72 [2] 57 7e [2] 5b 74 [2] 4c 7f [2] 57 31 [2] 6a }

  condition:
    any of them
}