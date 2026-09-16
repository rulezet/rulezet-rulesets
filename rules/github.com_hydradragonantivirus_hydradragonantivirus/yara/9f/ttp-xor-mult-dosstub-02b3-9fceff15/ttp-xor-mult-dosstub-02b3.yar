rule TTP_XOR_MULT_DOSStub_02b3 {
  strings:
    $key_02b3 = { 56 db [2] 22 c3 [2] 65 c1 [2] 22 d0 [2] 6c dc [2] 60 d6 [2] 77 dd [2] 6c 93 [2] 51 }

  condition:
    any of them
}