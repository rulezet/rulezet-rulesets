rule TTP_XOR_MULT_DOSStub_ceae {
  strings:
    $key_ceae = { 9a c6 [2] ee de [2] a9 dc [2] ee cd [2] a0 c1 [2] ac cb [2] bb c0 [2] a0 8e [2] 9d }

  condition:
    any of them
}