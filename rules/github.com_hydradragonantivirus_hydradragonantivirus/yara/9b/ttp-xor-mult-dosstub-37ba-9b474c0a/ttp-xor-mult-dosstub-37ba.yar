rule TTP_XOR_MULT_DOSStub_37ba {
  strings:
    $key_37ba = { 63 d2 [2] 17 ca [2] 50 c8 [2] 17 d9 [2] 59 d5 [2] 55 df [2] 42 d4 [2] 59 9a [2] 64 }

  condition:
    any of them
}