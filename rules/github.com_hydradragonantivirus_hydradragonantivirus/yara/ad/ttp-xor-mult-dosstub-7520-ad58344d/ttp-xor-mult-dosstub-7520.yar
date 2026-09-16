rule TTP_XOR_MULT_DOSStub_7520 {
  strings:
    $key_7520 = { 21 48 [2] 55 50 [2] 12 52 [2] 55 43 [2] 1b 4f [2] 17 45 [2] 00 4e [2] 1b 00 [2] 26 }

  condition:
    any of them
}