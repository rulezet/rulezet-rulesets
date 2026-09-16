rule TTP_XOR_MULT_DOSStub_49f2 {
  strings:
    $key_49f2 = { 1d 9a [2] 69 82 [2] 2e 80 [2] 69 91 [2] 27 9d [2] 2b 97 [2] 3c 9c [2] 27 d2 [2] 1a }

  condition:
    any of them
}