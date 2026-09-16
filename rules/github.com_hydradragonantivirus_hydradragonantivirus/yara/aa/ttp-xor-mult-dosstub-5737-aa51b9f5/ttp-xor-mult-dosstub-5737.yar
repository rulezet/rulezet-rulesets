rule TTP_XOR_MULT_DOSStub_5737 {
  strings:
    $key_5737 = { 03 5f [2] 77 47 [2] 30 45 [2] 77 54 [2] 39 58 [2] 35 52 [2] 22 59 [2] 39 17 [2] 04 }

  condition:
    any of them
}