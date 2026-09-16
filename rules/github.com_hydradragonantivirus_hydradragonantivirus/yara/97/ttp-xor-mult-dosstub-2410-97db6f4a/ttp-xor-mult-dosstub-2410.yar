rule TTP_XOR_MULT_DOSStub_2410 {
  strings:
    $key_2410 = { 70 78 [2] 04 60 [2] 43 62 [2] 04 73 [2] 4a 7f [2] 46 75 [2] 51 7e [2] 4a 30 [2] 77 }

  condition:
    any of them
}