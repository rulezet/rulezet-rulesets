rule TTP_XOR_MULT_DOSStub_55ba {
  strings:
    $key_55ba = { 01 d2 [2] 75 ca [2] 32 c8 [2] 75 d9 [2] 3b d5 [2] 37 df [2] 20 d4 [2] 3b 9a [2] 06 }

  condition:
    any of them
}