rule TTP_XOR_MULT_DOSStub_12ba {
  strings:
    $key_12ba = { 46 d2 [2] 32 ca [2] 75 c8 [2] 32 d9 [2] 7c d5 [2] 70 df [2] 67 d4 [2] 7c 9a [2] 41 }

  condition:
    any of them
}