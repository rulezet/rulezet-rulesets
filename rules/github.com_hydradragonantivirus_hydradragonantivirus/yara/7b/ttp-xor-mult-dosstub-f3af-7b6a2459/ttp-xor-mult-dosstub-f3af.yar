rule TTP_XOR_MULT_DOSStub_f3af {
  strings:
    $key_f3af = { a7 c7 [2] d3 df [2] 94 dd [2] d3 cc [2] 9d c0 [2] 91 ca [2] 86 c1 [2] 9d 8f [2] a0 }

  condition:
    any of them
}