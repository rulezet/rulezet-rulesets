rule TTP_XOR_MULT_DOSStub_f5af {
  strings:
    $key_f5af = { a1 c7 [2] d5 df [2] 92 dd [2] d5 cc [2] 9b c0 [2] 97 ca [2] 80 c1 [2] 9b 8f [2] a6 }

  condition:
    any of them
}