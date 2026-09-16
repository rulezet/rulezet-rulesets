rule TTP_XOR_MULT_DOSStub_2957 {
  strings:
    $key_2957 = { 7d 3f [2] 09 27 [2] 4e 25 [2] 09 34 [2] 47 38 [2] 4b 32 [2] 5c 39 [2] 47 77 [2] 7a }

  condition:
    any of them
}