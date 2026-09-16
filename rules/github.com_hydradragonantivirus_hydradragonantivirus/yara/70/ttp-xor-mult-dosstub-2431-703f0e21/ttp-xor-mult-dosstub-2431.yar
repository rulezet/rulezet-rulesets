rule TTP_XOR_MULT_DOSStub_2431 {
  strings:
    $key_2431 = { 70 59 [2] 04 41 [2] 43 43 [2] 04 52 [2] 4a 5e [2] 46 54 [2] 51 5f [2] 4a 11 [2] 77 }

  condition:
    any of them
}