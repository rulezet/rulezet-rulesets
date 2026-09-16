rule TTP_XOR_MULT_DOSStub_4d00 {
  strings:
    $key_4d00 = { 19 68 [2] 6d 70 [2] 2a 72 [2] 6d 63 [2] 23 6f [2] 2f 65 [2] 38 6e [2] 23 20 [2] 1e }

  condition:
    any of them
}