rule TTP_XOR_MULT_DOSStub_02ba {
  strings:
    $key_02ba = { 56 d2 [2] 22 ca [2] 65 c8 [2] 22 d9 [2] 6c d5 [2] 60 df [2] 77 d4 [2] 6c 9a [2] 51 }

  condition:
    any of them
}