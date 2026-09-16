rule TTP_XOR_MULT_DOSStub_7d11 {
  strings:
    $key_7d11 = { 29 79 [2] 5d 61 [2] 1a 63 [2] 5d 72 [2] 13 7e [2] 1f 74 [2] 08 7f [2] 13 31 [2] 2e }

  condition:
    any of them
}