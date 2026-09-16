rule TTP_XOR_MULT_DOSStub_3b67 {
  strings:
    $key_3b67 = { 6f 0f [2] 1b 17 [2] 5c 15 [2] 1b 04 [2] 55 08 [2] 59 02 [2] 4e 09 [2] 55 47 [2] 68 }

  condition:
    any of them
}