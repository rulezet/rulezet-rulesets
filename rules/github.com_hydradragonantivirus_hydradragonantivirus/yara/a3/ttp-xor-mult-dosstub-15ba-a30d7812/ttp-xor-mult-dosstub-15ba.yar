rule TTP_XOR_MULT_DOSStub_15ba {
  strings:
    $key_15ba = { 41 d2 [2] 35 ca [2] 72 c8 [2] 35 d9 [2] 7b d5 [2] 77 df [2] 60 d4 [2] 7b 9a [2] 46 }

  condition:
    any of them
}