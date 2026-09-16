rule TTP_XOR_MULT_DOSStub_49f4 {
  strings:
    $key_49f4 = { 1d 9c [2] 69 84 [2] 2e 86 [2] 69 97 [2] 27 9b [2] 2b 91 [2] 3c 9a [2] 27 d4 [2] 1a }

  condition:
    any of them
}