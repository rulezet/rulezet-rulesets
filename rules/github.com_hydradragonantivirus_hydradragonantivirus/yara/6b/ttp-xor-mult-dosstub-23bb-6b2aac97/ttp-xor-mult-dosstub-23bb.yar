rule TTP_XOR_MULT_DOSStub_23bb {
  strings:
    $key_23bb = { 77 d3 [2] 03 cb [2] 44 c9 [2] 03 d8 [2] 4d d4 [2] 41 de [2] 56 d5 [2] 4d 9b [2] 70 }

  condition:
    any of them
}