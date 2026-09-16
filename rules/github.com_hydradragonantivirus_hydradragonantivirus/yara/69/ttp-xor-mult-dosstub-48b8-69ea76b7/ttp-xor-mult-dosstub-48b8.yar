rule TTP_XOR_MULT_DOSStub_48b8 {
  strings:
    $key_48b8 = { 1c d0 [2] 68 c8 [2] 2f ca [2] 68 db [2] 26 d7 [2] 2a dd [2] 3d d6 [2] 26 98 [2] 1b }

  condition:
    any of them
}