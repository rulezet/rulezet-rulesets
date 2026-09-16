rule TTP_XOR_MULT_DOSStub_3900 {
  strings:
    $key_3900 = { 6d 68 [2] 19 70 [2] 5e 72 [2] 19 63 [2] 57 6f [2] 5b 65 [2] 4c 6e [2] 57 20 [2] 6a }

  condition:
    any of them
}