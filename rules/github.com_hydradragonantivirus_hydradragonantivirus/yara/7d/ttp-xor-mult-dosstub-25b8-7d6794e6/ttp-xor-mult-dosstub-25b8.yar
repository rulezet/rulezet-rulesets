rule TTP_XOR_MULT_DOSStub_25b8 {
  strings:
    $key_25b8 = { 71 d0 [2] 05 c8 [2] 42 ca [2] 05 db [2] 4b d7 [2] 47 dd [2] 50 d6 [2] 4b 98 [2] 76 }

  condition:
    any of them
}