rule TTP_XOR_MULT_DOSStub_f6af {
  strings:
    $key_f6af = { a2 c7 [2] d6 df [2] 91 dd [2] d6 cc [2] 98 c0 [2] 94 ca [2] 83 c1 [2] 98 8f [2] a5 }

  condition:
    any of them
}