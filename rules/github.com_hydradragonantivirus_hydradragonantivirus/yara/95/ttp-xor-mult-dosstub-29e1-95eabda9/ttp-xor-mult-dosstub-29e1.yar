rule TTP_XOR_MULT_DOSStub_29e1 {
  strings:
    $key_29e1 = { 7d 89 [2] 09 91 [2] 4e 93 [2] 09 82 [2] 47 8e [2] 4b 84 [2] 5c 8f [2] 47 c1 [2] 7a }

  condition:
    any of them
}