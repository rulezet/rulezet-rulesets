rule TTP_XOR_MULT_DOSStub_62ba {
  strings:
    $key_62ba = { 36 d2 [2] 42 ca [2] 05 c8 [2] 42 d9 [2] 0c d5 [2] 00 df [2] 17 d4 [2] 0c 9a [2] 31 }

  condition:
    any of them
}