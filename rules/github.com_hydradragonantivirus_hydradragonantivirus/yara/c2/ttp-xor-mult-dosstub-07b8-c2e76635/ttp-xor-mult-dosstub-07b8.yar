rule TTP_XOR_MULT_DOSStub_07b8 {
  strings:
    $key_07b8 = { 53 d0 [2] 27 c8 [2] 60 ca [2] 27 db [2] 69 d7 [2] 65 dd [2] 72 d6 [2] 69 98 [2] 54 }

  condition:
    any of them
}