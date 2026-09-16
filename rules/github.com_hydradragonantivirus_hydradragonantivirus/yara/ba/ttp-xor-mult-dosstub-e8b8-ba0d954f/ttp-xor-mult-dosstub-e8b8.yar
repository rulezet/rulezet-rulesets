rule TTP_XOR_MULT_DOSStub_e8b8 {
  strings:
    $key_e8b8 = { bc d0 [2] c8 c8 [2] 8f ca [2] c8 db [2] 86 d7 [2] 8a dd [2] 9d d6 [2] 86 98 [2] bb }

  condition:
    any of them
}