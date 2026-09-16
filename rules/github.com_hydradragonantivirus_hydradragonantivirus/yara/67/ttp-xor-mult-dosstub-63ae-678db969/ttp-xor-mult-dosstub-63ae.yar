rule TTP_XOR_MULT_DOSStub_63ae {
  strings:
    $key_63ae = { 37 c6 [2] 43 de [2] 04 dc [2] 43 cd [2] 0d c1 [2] 01 cb [2] 16 c0 [2] 0d 8e [2] 30 }

  condition:
    any of them
}