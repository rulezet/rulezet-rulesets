rule TTP_XOR_MULT_DOSStub_7b67 {
  strings:
    $key_7b67 = { 2f 0f [2] 5b 17 [2] 1c 15 [2] 5b 04 [2] 15 08 [2] 19 02 [2] 0e 09 [2] 15 47 [2] 28 }

  condition:
    any of them
}