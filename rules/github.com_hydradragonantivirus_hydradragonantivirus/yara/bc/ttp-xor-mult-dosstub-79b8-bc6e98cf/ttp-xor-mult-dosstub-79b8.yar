rule TTP_XOR_MULT_DOSStub_79b8 {
  strings:
    $key_79b8 = { 2d d0 [2] 59 c8 [2] 1e ca [2] 59 db [2] 17 d7 [2] 1b dd [2] 0c d6 [2] 17 98 [2] 2a }

  condition:
    any of them
}