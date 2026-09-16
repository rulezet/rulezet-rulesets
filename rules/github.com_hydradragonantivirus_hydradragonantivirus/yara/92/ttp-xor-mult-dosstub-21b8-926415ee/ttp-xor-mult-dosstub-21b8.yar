rule TTP_XOR_MULT_DOSStub_21b8 {
  strings:
    $key_21b8 = { 75 d0 [2] 01 c8 [2] 46 ca [2] 01 db [2] 4f d7 [2] 43 dd [2] 54 d6 [2] 4f 98 [2] 72 }

  condition:
    any of them
}