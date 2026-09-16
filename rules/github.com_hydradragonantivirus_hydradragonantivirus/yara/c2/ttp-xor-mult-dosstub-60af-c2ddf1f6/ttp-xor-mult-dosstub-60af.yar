rule TTP_XOR_MULT_DOSStub_60af {
  strings:
    $key_60af = { 34 c7 [2] 40 df [2] 07 dd [2] 40 cc [2] 0e c0 [2] 02 ca [2] 15 c1 [2] 0e 8f [2] 33 }

  condition:
    any of them
}