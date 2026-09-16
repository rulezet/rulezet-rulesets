rule TTP_XOR_MULT_DOSStub_3931 {
  strings:
    $key_3931 = { 6d 59 [2] 19 41 [2] 5e 43 [2] 19 52 [2] 57 5e [2] 5b 54 [2] 4c 5f [2] 57 11 [2] 6a }

  condition:
    any of them
}