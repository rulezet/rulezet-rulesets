rule TTP_XOR_MULT_DOSStub_5771 {
  strings:
    $key_5771 = { 03 19 [2] 77 01 [2] 30 03 [2] 77 12 [2] 39 1e [2] 35 14 [2] 22 1f [2] 39 51 [2] 04 }

  condition:
    any of them
}