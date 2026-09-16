rule TTP_XOR_MULT_DOSStub_25ba {
  strings:
    $key_25ba = { 71 d2 [2] 05 ca [2] 42 c8 [2] 05 d9 [2] 4b d5 [2] 47 df [2] 50 d4 [2] 4b 9a [2] 76 }

  condition:
    any of them
}