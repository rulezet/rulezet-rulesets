rule TTP_XOR_MULT_DOSStub_a863 {
  strings:
    $key_a863 = { fc 0b [2] 88 13 [2] cf 11 [2] 88 00 [2] c6 0c [2] ca 06 [2] dd 0d [2] c6 43 [2] fb }

  condition:
    any of them
}