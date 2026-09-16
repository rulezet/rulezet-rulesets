rule TTP_XOR_MULT_DOSStub_13b8 {
  strings:
    $key_13b8 = { 47 d0 [2] 33 c8 [2] 74 ca [2] 33 db [2] 7d d7 [2] 71 dd [2] 66 d6 [2] 7d 98 [2] 40 }

  condition:
    any of them
}