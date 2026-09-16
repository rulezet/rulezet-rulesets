rule TTP_XOR_MULT_DOSStub_c5af {
  strings:
    $key_c5af = { 91 c7 [2] e5 df [2] a2 dd [2] e5 cc [2] ab c0 [2] a7 ca [2] b0 c1 [2] ab 8f [2] 96 }

  condition:
    any of them
}