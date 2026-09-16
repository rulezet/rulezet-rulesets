rule TTP_XOR_MULT_DOSStub_a8fc {
  strings:
    $key_a8fc = { fc 94 [2] 88 8c [2] cf 8e [2] 88 9f [2] c6 93 [2] ca 99 [2] dd 92 [2] c6 dc [2] fb }

  condition:
    any of them
}