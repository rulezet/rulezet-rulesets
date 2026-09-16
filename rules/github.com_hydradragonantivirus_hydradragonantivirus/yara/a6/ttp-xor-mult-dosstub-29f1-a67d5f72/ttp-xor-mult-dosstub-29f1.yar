rule TTP_XOR_MULT_DOSStub_29f1 {
  strings:
    $key_29f1 = { 7d 99 [2] 09 81 [2] 4e 83 [2] 09 92 [2] 47 9e [2] 4b 94 [2] 5c 9f [2] 47 d1 [2] 7a }

  condition:
    any of them
}