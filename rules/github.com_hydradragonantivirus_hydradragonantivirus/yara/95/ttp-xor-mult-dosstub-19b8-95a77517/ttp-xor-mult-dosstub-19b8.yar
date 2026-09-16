rule TTP_XOR_MULT_DOSStub_19b8 {
  strings:
    $key_19b8 = { 4d d0 [2] 39 c8 [2] 7e ca [2] 39 db [2] 77 d7 [2] 7b dd [2] 6c d6 [2] 77 98 [2] 4a }

  condition:
    any of them
}