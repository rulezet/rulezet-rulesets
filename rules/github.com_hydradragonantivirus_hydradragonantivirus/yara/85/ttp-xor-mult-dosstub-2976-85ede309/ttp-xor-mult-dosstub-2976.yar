rule TTP_XOR_MULT_DOSStub_2976 {
  strings:
    $key_2976 = { 7d 1e [2] 09 06 [2] 4e 04 [2] 09 15 [2] 47 19 [2] 4b 13 [2] 5c 18 [2] 47 56 [2] 7a }

  condition:
    any of them
}