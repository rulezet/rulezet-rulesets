rule TTP_XOR_MULT_DOSStub_72b8 {
  strings:
    $key_72b8 = { 26 d0 [2] 52 c8 [2] 15 ca [2] 52 db [2] 1c d7 [2] 10 dd [2] 07 d6 [2] 1c 98 [2] 21 }

  condition:
    any of them
}