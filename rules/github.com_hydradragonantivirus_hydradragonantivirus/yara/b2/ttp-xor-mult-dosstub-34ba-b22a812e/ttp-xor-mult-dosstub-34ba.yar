rule TTP_XOR_MULT_DOSStub_34ba {
  strings:
    $key_34ba = { 60 d2 [2] 14 ca [2] 53 c8 [2] 14 d9 [2] 5a d5 [2] 56 df [2] 41 d4 [2] 5a 9a [2] 67 }

  condition:
    any of them
}