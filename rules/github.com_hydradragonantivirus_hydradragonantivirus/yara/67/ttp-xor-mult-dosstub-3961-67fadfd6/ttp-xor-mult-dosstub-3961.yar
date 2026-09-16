rule TTP_XOR_MULT_DOSStub_3961 {
  strings:
    $key_3961 = { 6d 09 [2] 19 11 [2] 5e 13 [2] 19 02 [2] 57 0e [2] 5b 04 [2] 4c 0f [2] 57 41 [2] 6a }

  condition:
    any of them
}