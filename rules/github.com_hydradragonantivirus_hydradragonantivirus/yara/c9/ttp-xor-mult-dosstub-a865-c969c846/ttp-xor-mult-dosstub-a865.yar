rule TTP_XOR_MULT_DOSStub_a865 {
  strings:
    $key_a865 = { fc 0d [2] 88 15 [2] cf 17 [2] 88 06 [2] c6 0a [2] ca 00 [2] dd 0b [2] c6 45 [2] fb }

  condition:
    any of them
}