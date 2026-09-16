rule TTP_XOR_MULT_DOSStub_b2ae {
  strings:
    $key_b2ae = { e6 c6 [2] 92 de [2] d5 dc [2] 92 cd [2] dc c1 [2] d0 cb [2] c7 c0 [2] dc 8e [2] e1 }

  condition:
    any of them
}