rule TTP_XOR_MULT_DOSStub_f0af {
  strings:
    $key_f0af = { a4 c7 [2] d0 df [2] 97 dd [2] d0 cc [2] 9e c0 [2] 92 ca [2] 85 c1 [2] 9e 8f [2] a3 }

  condition:
    any of them
}