rule TTP_XOR_MULT_DOSStub_2421 {
  strings:
    $key_2421 = { 70 49 [2] 04 51 [2] 43 53 [2] 04 42 [2] 4a 4e [2] 46 44 [2] 51 4f [2] 4a 01 [2] 77 }

  condition:
    any of them
}