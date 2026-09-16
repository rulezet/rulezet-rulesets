rule TTP_XOR_MULT_DOSStub_2907 {
  strings:
    $key_2907 = { 7d 6f [2] 09 77 [2] 4e 75 [2] 09 64 [2] 47 68 [2] 4b 62 [2] 5c 69 [2] 47 27 [2] 7a }

  condition:
    any of them
}