rule TTP_XOR_MULT_DOSStub_13b5 {
  strings:
    $key_13b5 = { 47 dd [2] 33 c5 [2] 74 c7 [2] 33 d6 [2] 7d da [2] 71 d0 [2] 66 db [2] 7d 95 [2] 40 }

  condition:
    any of them
}