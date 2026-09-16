rule TTP_XOR_MULT_DOSStub_0920 {
  strings:
    $key_0920 = { 5d 48 [2] 29 50 [2] 6e 52 [2] 29 43 [2] 67 4f [2] 6b 45 [2] 7c 4e [2] 67 00 [2] 5a }

  condition:
    any of them
}