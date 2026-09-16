rule TTP_XOR_MULT_DOSStub_41ba {
  strings:
    $key_41ba = { 15 d2 [2] 61 ca [2] 26 c8 [2] 61 d9 [2] 2f d5 [2] 23 df [2] 34 d4 [2] 2f 9a [2] 12 }

  condition:
    any of them
}