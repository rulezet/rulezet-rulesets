rule TTP_XOR_MULT_DOSStub_39e1 {
  strings:
    $key_39e1 = { 6d 89 [2] 19 91 [2] 5e 93 [2] 19 82 [2] 57 8e [2] 5b 84 [2] 4c 8f [2] 57 c1 [2] 6a }

  condition:
    any of them
}