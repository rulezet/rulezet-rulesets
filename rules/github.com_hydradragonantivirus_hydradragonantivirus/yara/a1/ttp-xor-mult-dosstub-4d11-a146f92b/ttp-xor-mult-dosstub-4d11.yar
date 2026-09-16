rule TTP_XOR_MULT_DOSStub_4d11 {
  strings:
    $key_4d11 = { 19 79 [2] 6d 61 [2] 2a 63 [2] 6d 72 [2] 23 7e [2] 2f 74 [2] 38 7f [2] 23 31 [2] 1e }

  condition:
    any of them
}