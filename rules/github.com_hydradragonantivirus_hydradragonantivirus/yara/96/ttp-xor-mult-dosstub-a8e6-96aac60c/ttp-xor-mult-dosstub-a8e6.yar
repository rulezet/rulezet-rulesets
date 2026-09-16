rule TTP_XOR_MULT_DOSStub_a8e6 {
  strings:
    $key_a8e6 = { fc 8e [2] 88 96 [2] cf 94 [2] 88 85 [2] c6 89 [2] ca 83 [2] dd 88 [2] c6 c6 [2] fb }

  condition:
    any of them
}