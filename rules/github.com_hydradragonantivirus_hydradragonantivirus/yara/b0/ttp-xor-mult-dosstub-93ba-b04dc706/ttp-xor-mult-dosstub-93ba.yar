rule TTP_XOR_MULT_DOSStub_93ba {
  strings:
    $key_93ba = { c7 d2 [2] b3 ca [2] f4 c8 [2] b3 d9 [2] fd d5 [2] f1 df [2] e6 d4 [2] fd 9a [2] c0 }

  condition:
    any of them
}