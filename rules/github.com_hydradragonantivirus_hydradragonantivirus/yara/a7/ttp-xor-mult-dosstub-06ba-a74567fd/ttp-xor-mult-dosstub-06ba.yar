rule TTP_XOR_MULT_DOSStub_06ba {
  strings:
    $key_06ba = { 52 d2 [2] 26 ca [2] 61 c8 [2] 26 d9 [2] 68 d5 [2] 64 df [2] 73 d4 [2] 68 9a [2] 55 }

  condition:
    any of them
}