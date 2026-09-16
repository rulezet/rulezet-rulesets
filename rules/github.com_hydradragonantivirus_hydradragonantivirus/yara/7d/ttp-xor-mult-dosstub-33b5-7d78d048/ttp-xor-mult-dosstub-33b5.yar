rule TTP_XOR_MULT_DOSStub_33b5 {
  strings:
    $key_33b5 = { 67 dd [2] 13 c5 [2] 54 c7 [2] 13 d6 [2] 5d da [2] 51 d0 [2] 46 db [2] 5d 95 [2] 60 }

  condition:
    any of them
}