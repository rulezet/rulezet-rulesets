rule TTP_XOR_MULT_DOSStub_c2af {
  strings:
    $key_c2af = { 96 c7 [2] e2 df [2] a5 dd [2] e2 cc [2] ac c0 [2] a0 ca [2] b7 c1 [2] ac 8f [2] 91 }

  condition:
    any of them
}