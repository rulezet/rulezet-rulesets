rule TTP_XOR_MULT_DOSStub_16b8 {
  strings:
    $key_16b8 = { 42 d0 [2] 36 c8 [2] 71 ca [2] 36 db [2] 78 d7 [2] 74 dd [2] 63 d6 [2] 78 98 [2] 45 }

  condition:
    any of them
}