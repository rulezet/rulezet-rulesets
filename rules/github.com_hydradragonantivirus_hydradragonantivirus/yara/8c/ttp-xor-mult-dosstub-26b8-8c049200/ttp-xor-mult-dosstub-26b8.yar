rule TTP_XOR_MULT_DOSStub_26b8 {
  strings:
    $key_26b8 = { 72 d0 [2] 06 c8 [2] 41 ca [2] 06 db [2] 48 d7 [2] 44 dd [2] 53 d6 [2] 48 98 [2] 75 }

  condition:
    any of them
}