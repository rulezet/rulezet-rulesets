rule TTP_XOR_MULT_DOSStub_57b8 {
  strings:
    $key_57b8 = { 03 d0 [2] 77 c8 [2] 30 ca [2] 77 db [2] 39 d7 [2] 35 dd [2] 22 d6 [2] 39 98 [2] 04 }

  condition:
    any of them
}