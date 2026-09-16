rule TTP_XOR_MULT_DOSStub_14ba {
  strings:
    $key_14ba = { 40 d2 [2] 34 ca [2] 73 c8 [2] 34 d9 [2] 7a d5 [2] 76 df [2] 61 d4 [2] 7a 9a [2] 47 }

  condition:
    any of them
}