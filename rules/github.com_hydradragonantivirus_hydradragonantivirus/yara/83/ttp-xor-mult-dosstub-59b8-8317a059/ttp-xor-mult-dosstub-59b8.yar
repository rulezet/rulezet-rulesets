rule TTP_XOR_MULT_DOSStub_59b8 {
  strings:
    $key_59b8 = { 0d d0 [2] 79 c8 [2] 3e ca [2] 79 db [2] 37 d7 [2] 3b dd [2] 2c d6 [2] 37 98 [2] 0a }

  condition:
    any of them
}