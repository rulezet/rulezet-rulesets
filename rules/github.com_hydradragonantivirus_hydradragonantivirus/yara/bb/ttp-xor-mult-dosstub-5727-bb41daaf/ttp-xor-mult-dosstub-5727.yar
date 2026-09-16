rule TTP_XOR_MULT_DOSStub_5727 {
  strings:
    $key_5727 = { 03 4f [2] 77 57 [2] 30 55 [2] 77 44 [2] 39 48 [2] 35 42 [2] 22 49 [2] 39 07 [2] 04 }

  condition:
    any of them
}