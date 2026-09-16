rule TTP_XOR_MULT_DOSStub_29e6 {
  strings:
    $key_29e6 = { 7d 8e [2] 09 96 [2] 4e 94 [2] 09 85 [2] 47 89 [2] 4b 83 [2] 5c 88 [2] 47 c6 [2] 7a }

  condition:
    any of them
}