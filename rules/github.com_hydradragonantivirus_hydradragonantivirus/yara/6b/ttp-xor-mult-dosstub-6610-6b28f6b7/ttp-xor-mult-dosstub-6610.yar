rule TTP_XOR_MULT_DOSStub_6610 {
  strings:
    $key_6610 = { 32 78 [2] 46 60 [2] 01 62 [2] 46 73 [2] 08 7f [2] 04 75 [2] 13 7e [2] 08 30 [2] 35 }

  condition:
    any of them
}