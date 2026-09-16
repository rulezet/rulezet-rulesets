rule TTP_XOR_MULT_DOSStub_d0af {
  strings:
    $key_d0af = { 84 c7 [2] f0 df [2] b7 dd [2] f0 cc [2] be c0 [2] b2 ca [2] a5 c1 [2] be 8f [2] 83 }

  condition:
    any of them
}