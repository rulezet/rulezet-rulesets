rule TTP_XOR_MULT_DOSStub_2107 {
  strings:
    $key_2107 = { 75 6f [2] 01 77 [2] 46 75 [2] 01 64 [2] 4f 68 [2] 43 62 [2] 54 69 [2] 4f 27 [2] 72 }

  condition:
    any of them
}