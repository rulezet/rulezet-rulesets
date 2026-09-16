rule TTP_XOR_MULT_DOSStub_2710 {
  strings:
    $key_2710 = { 73 78 [2] 07 60 [2] 40 62 [2] 07 73 [2] 49 7f [2] 45 75 [2] 52 7e [2] 49 30 [2] 74 }

  condition:
    any of them
}