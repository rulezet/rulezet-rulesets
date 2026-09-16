rule TTP_XOR_MULT_DOSStub_53b5 {
  strings:
    $key_53b5 = { 07 dd [2] 73 c5 [2] 34 c7 [2] 73 d6 [2] 3d da [2] 31 d0 [2] 26 db [2] 3d 95 [2] 00 }

  condition:
    any of them
}