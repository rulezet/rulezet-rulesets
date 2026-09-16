rule TTP_XOR_MULT_DOSStub_7e77 {
  strings:
    $key_7e77 = { 2a 1f [2] 5e 07 [2] 19 05 [2] 5e 14 [2] 10 18 [2] 1c 12 [2] 0b 19 [2] 10 57 [2] 2d }

  condition:
    any of them
}