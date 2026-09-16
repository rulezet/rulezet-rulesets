rule TTP_XOR_MULT_DOSStub_e8cb {
  strings:
    $key_e8cb = { bc a3 [2] c8 bb [2] 8f b9 [2] c8 a8 [2] 86 a4 [2] 8a ae [2] 9d a5 [2] 86 eb [2] bb }

  condition:
    any of them
}