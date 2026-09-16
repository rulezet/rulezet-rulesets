rule TTP_XOR_MULT_DOSStub_6b00 {
  strings:
    $key_6b00 = { 3f 68 [2] 4b 70 [2] 0c 72 [2] 4b 63 [2] 05 6f [2] 09 65 [2] 1e 6e [2] 05 20 [2] 38 }

  condition:
    any of them
}