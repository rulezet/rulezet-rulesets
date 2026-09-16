rule TTP_XOR_MULT_DOSStub_6b20 {
  strings:
    $key_6b20 = { 3f 48 [2] 4b 50 [2] 0c 52 [2] 4b 43 [2] 05 4f [2] 09 45 [2] 1e 4e [2] 05 00 [2] 38 }

  condition:
    any of them
}