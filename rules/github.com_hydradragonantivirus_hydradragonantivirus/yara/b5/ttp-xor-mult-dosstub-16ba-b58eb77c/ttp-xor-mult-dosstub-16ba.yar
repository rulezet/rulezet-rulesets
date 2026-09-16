rule TTP_XOR_MULT_DOSStub_16ba {
  strings:
    $key_16ba = { 42 d2 [2] 36 ca [2] 71 c8 [2] 36 d9 [2] 78 d5 [2] 74 df [2] 63 d4 [2] 78 9a [2] 45 }

  condition:
    any of them
}