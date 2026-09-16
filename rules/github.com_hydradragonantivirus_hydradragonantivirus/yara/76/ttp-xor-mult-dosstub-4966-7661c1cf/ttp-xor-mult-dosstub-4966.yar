rule TTP_XOR_MULT_DOSStub_4966 {
  strings:
    $key_4966 = { 1d 0e [2] 69 16 [2] 2e 14 [2] 69 05 [2] 27 09 [2] 2b 03 [2] 3c 08 [2] 27 46 [2] 1a }

  condition:
    any of them
}