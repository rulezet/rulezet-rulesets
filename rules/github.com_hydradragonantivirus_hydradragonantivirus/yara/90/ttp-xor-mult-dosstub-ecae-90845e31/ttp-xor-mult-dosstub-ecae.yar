rule TTP_XOR_MULT_DOSStub_ecae {
  strings:
    $key_ecae = { b8 c6 [2] cc de [2] 8b dc [2] cc cd [2] 82 c1 [2] 8e cb [2] 99 c0 [2] 82 8e [2] bf }

  condition:
    any of them
}