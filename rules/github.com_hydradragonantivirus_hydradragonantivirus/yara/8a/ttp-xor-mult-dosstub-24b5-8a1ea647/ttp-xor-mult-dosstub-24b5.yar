rule TTP_XOR_MULT_DOSStub_24b5 {
  strings:
    $key_24b5 = { 70 dd [2] 04 c5 [2] 43 c7 [2] 04 d6 [2] 4a da [2] 46 d0 [2] 51 db [2] 4a 95 [2] 77 }

  condition:
    any of them
}