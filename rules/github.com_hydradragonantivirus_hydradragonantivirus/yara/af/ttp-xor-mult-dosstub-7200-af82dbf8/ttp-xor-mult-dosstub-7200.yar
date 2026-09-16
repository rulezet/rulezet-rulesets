rule TTP_XOR_MULT_DOSStub_7200 {
  strings:
    $key_7200 = { 26 68 [2] 52 70 [2] 15 72 [2] 52 63 [2] 1c 6f [2] 10 65 [2] 07 6e [2] 1c 20 [2] 21 }

  condition:
    any of them
}