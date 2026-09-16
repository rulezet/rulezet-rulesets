rule TTP_XOR_MULT_DOSStub_1a67 {
  strings:
    $key_1a67 = { 4e 0f [2] 3a 17 [2] 7d 15 [2] 3a 04 [2] 74 08 [2] 78 02 [2] 6f 09 [2] 74 47 [2] 49 }

  condition:
    any of them
}