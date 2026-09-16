rule TTP_XOR_MULT_DOSStub_b1ae {
  strings:
    $key_b1ae = { e5 c6 [2] 91 de [2] d6 dc [2] 91 cd [2] df c1 [2] d3 cb [2] c4 c0 [2] df 8e [2] e2 }

  condition:
    any of them
}