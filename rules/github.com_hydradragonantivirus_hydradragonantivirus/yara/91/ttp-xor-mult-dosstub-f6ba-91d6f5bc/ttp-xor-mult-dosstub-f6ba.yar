rule TTP_XOR_MULT_DOSStub_f6ba {
  strings:
    $key_f6ba = { a2 d2 [2] d6 ca [2] 91 c8 [2] d6 d9 [2] 98 d5 [2] 94 df [2] 83 d4 [2] 98 9a [2] a5 }

  condition:
    any of them
}