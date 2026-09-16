rule TTP_XOR_MULT_DOSStub_e81b {
  strings:
    $key_e81b = { bc 73 [2] c8 6b [2] 8f 69 [2] c8 78 [2] 86 74 [2] 8a 7e [2] 9d 75 [2] 86 3b [2] bb }

  condition:
    any of them
}