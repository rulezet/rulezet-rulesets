rule TTP_XOR_MULT_DOSStub_a8ee {
  strings:
    $key_a8ee = { fc 86 [2] 88 9e [2] cf 9c [2] 88 8d [2] c6 81 [2] ca 8b [2] dd 80 [2] c6 ce [2] fb }

  condition:
    any of them
}