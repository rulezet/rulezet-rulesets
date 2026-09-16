rule TTP_XOR_MULT_DOSStub_d3af {
  strings:
    $key_d3af = { 87 c7 [2] f3 df [2] b4 dd [2] f3 cc [2] bd c0 [2] b1 ca [2] a6 c1 [2] bd 8f [2] 80 }

  condition:
    any of them
}