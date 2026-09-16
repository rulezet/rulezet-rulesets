rule TTP_XOR_MULT_DOSStub_7157 {
  strings:
    $key_7157 = { 25 3f [2] 51 27 [2] 16 25 [2] 51 34 [2] 1f 38 [2] 13 32 [2] 04 39 [2] 1f 77 [2] 22 }

  condition:
    any of them
}