rule TTP_XOR_MULT_DOSStub_7710 {
  strings:
    $key_7710 = { 23 78 [2] 57 60 [2] 10 62 [2] 57 73 [2] 19 7f [2] 15 75 [2] 02 7e [2] 19 30 [2] 24 }

  condition:
    any of them
}