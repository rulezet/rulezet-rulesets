rule TTP_XOR_MULT_DOSStub_e2ad {
  strings:
    $key_e2ad = { b6 c5 [2] c2 dd [2] 85 df [2] c2 ce [2] 8c c2 [2] 80 c8 [2] 97 c3 [2] 8c 8d [2] b1 }

  condition:
    any of them
}