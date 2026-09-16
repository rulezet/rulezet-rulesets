rule TTP_XOR_MULT_DOSStub_b2ba {
  strings:
    $key_b2ba = { e6 d2 [2] 92 ca [2] d5 c8 [2] 92 d9 [2] dc d5 [2] d0 df [2] c7 d4 [2] dc 9a [2] e1 }

  condition:
    any of them
}