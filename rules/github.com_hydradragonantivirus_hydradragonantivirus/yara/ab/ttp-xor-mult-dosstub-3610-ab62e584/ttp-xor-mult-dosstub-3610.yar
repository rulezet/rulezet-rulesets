rule TTP_XOR_MULT_DOSStub_3610 {
  strings:
    $key_3610 = { 62 78 [2] 16 60 [2] 51 62 [2] 16 73 [2] 58 7f [2] 54 75 [2] 43 7e [2] 58 30 [2] 65 }

  condition:
    any of them
}