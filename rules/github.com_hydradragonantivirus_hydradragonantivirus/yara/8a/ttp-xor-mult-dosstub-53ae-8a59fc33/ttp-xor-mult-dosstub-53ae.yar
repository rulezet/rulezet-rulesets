rule TTP_XOR_MULT_DOSStub_53ae {
  strings:
    $key_53ae = { 07 c6 [2] 73 de [2] 34 dc [2] 73 cd [2] 3d c1 [2] 31 cb [2] 26 c0 [2] 3d 8e [2] 00 }

  condition:
    any of them
}