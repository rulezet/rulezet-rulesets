rule TTP_XOR_MULT_DOSStub_93af {
  strings:
    $key_93af = { c7 c7 [2] b3 df [2] f4 dd [2] b3 cc [2] fd c0 [2] f1 ca [2] e6 c1 [2] fd 8f [2] c0 }

  condition:
    any of them
}