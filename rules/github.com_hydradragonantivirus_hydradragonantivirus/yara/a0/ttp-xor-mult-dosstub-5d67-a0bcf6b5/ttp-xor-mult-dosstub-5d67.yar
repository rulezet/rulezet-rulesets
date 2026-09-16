rule TTP_XOR_MULT_DOSStub_5d67 {
  strings:
    $key_5d67 = { 09 0f [2] 7d 17 [2] 3a 15 [2] 7d 04 [2] 33 08 [2] 3f 02 [2] 28 09 [2] 33 47 [2] 0e }

  condition:
    any of them
}