rule TTP_XOR_MULT_DOSStub_05ba {
  strings:
    $key_05ba = { 51 d2 [2] 25 ca [2] 62 c8 [2] 25 d9 [2] 6b d5 [2] 67 df [2] 70 d4 [2] 6b 9a [2] 56 }

  condition:
    any of them
}