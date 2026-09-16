rule TTP_XOR_MULT_DOSStub_f3bc {
  strings:
    $key_f3bc = { a7 d4 [2] d3 cc [2] 94 ce [2] d3 df [2] 9d d3 [2] 91 d9 [2] 86 d2 [2] 9d 9c [2] a0 }

  condition:
    any of them
}