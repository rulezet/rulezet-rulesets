rule TTP_XOR_MULT_DOSStub_4967 {
  strings:
    $key_4967 = { 1d 0f [2] 69 17 [2] 2e 15 [2] 69 04 [2] 27 08 [2] 2b 02 [2] 3c 09 [2] 27 47 [2] 1a }

  condition:
    any of them
}