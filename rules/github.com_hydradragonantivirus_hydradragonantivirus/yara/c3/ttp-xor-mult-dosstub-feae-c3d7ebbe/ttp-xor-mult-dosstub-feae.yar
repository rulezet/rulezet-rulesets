rule TTP_XOR_MULT_DOSStub_feae {
  strings:
    $key_feae = { aa c6 [2] de de [2] 99 dc [2] de cd [2] 90 c1 [2] 9c cb [2] 8b c0 [2] 90 8e [2] ad }

  condition:
    any of them
}