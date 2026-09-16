rule TTP_XOR_MULT_DOSStub_5710 {
  strings:
    $key_5710 = { 03 78 [2] 77 60 [2] 30 62 [2] 77 73 [2] 39 7f [2] 35 75 [2] 22 7e [2] 39 30 [2] 04 }

  condition:
    any of them
}