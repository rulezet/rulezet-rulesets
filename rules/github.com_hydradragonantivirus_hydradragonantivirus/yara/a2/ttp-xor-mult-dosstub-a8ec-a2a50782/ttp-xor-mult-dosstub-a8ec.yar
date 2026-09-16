rule TTP_XOR_MULT_DOSStub_a8ec {
  strings:
    $key_a8ec = { fc 84 [2] 88 9c [2] cf 9e [2] 88 8f [2] c6 83 [2] ca 89 [2] dd 82 [2] c6 cc [2] fb }

  condition:
    any of them
}