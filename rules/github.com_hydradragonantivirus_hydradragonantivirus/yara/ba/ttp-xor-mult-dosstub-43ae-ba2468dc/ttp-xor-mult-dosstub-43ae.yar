rule TTP_XOR_MULT_DOSStub_43ae {
  strings:
    $key_43ae = { 17 c6 [2] 63 de [2] 24 dc [2] 63 cd [2] 2d c1 [2] 21 cb [2] 36 c0 [2] 2d 8e [2] 10 }

  condition:
    any of them
}