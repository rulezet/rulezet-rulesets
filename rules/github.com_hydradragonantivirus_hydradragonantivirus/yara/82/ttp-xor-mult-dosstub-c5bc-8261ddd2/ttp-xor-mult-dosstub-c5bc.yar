rule TTP_XOR_MULT_DOSStub_c5bc {
  strings:
    $key_c5bc = { 91 d4 [2] e5 cc [2] a2 ce [2] e5 df [2] ab d3 [2] a7 d9 [2] b0 d2 [2] ab 9c [2] 96 }

  condition:
    any of them
}