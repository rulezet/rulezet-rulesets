rule TTP_XOR_MULT_DOSStub_6200 {
  strings:
    $key_6200 = { 36 68 [2] 42 70 [2] 05 72 [2] 42 63 [2] 0c 6f [2] 00 65 [2] 17 6e [2] 0c 20 [2] 31 }

  condition:
    any of them
}