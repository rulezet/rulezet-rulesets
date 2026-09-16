rule TTP_XOR_MULT_DOSStub_2610 {
  strings:
    $key_2610 = { 72 78 [2] 06 60 [2] 41 62 [2] 06 73 [2] 48 7f [2] 44 75 [2] 53 7e [2] 48 30 [2] 75 }

  condition:
    any of them
}