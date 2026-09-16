rule TTP_XOR_MULT_DOSStub_34b5 {
  strings:
    $key_34b5 = { 60 dd [2] 14 c5 [2] 53 c7 [2] 14 d6 [2] 5a da [2] 56 d0 [2] 41 db [2] 5a 95 [2] 67 }

  condition:
    any of them
}