rule TTP_XOR_MULT_DOSStub_65ba {
  strings:
    $key_65ba = { 31 d2 [2] 45 ca [2] 02 c8 [2] 45 d9 [2] 0b d5 [2] 07 df [2] 10 d4 [2] 0b 9a [2] 36 }

  condition:
    any of them
}