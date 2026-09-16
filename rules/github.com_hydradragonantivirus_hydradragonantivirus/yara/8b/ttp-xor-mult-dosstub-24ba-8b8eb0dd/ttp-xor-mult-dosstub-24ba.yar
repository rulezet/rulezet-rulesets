rule TTP_XOR_MULT_DOSStub_24ba {
  strings:
    $key_24ba = { 70 d2 [2] 04 ca [2] 43 c8 [2] 04 d9 [2] 4a d5 [2] 46 df [2] 51 d4 [2] 4a 9a [2] 77 }

  condition:
    any of them
}