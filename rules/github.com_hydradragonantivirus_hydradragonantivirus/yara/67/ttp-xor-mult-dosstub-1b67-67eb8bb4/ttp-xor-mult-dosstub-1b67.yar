rule TTP_XOR_MULT_DOSStub_1b67 {
  strings:
    $key_1b67 = { 4f 0f [2] 3b 17 [2] 7c 15 [2] 3b 04 [2] 75 08 [2] 79 02 [2] 6e 09 [2] 75 47 [2] 48 }

  condition:
    any of them
}