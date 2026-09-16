rule TTP_XOR_MULT_DOSStub_4b67 {
  strings:
    $key_4b67 = { 1f 0f [2] 6b 17 [2] 2c 15 [2] 6b 04 [2] 25 08 [2] 29 02 [2] 3e 09 [2] 25 47 [2] 18 }

  condition:
    any of them
}