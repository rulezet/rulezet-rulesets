rule TTP_XOR_MULT_DOSStub_d7af {
  strings:
    $key_d7af = { 83 c7 [2] f7 df [2] b0 dd [2] f7 cc [2] b9 c0 [2] b5 ca [2] a2 c1 [2] b9 8f [2] 84 }

  condition:
    any of them
}