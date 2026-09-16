rule TTP_XOR_MULT_DOSStub_72ba {
  strings:
    $key_72ba = { 26 d2 [2] 52 ca [2] 15 c8 [2] 52 d9 [2] 1c d5 [2] 10 df [2] 07 d4 [2] 1c 9a [2] 21 }

  condition:
    any of them
}