rule TTP_XOR_MULT_DOSStub_21ba {
  strings:
    $key_21ba = { 75 d2 [2] 01 ca [2] 46 c8 [2] 01 d9 [2] 4f d5 [2] 43 df [2] 54 d4 [2] 4f 9a [2] 72 }

  condition:
    any of them
}