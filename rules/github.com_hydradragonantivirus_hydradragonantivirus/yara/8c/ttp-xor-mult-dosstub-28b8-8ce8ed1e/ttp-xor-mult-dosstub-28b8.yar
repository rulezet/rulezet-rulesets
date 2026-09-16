rule TTP_XOR_MULT_DOSStub_28b8 {
  strings:
    $key_28b8 = { 7c d0 [2] 08 c8 [2] 4f ca [2] 08 db [2] 46 d7 [2] 4a dd [2] 5d d6 [2] 46 98 [2] 7b }

  condition:
    any of them
}