rule TTP_XOR_MULT_DOSStub_a820 {
  strings:
    $key_a820 = { fc 48 [2] 88 50 [2] cf 52 [2] 88 43 [2] c6 4f [2] ca 45 [2] dd 4e [2] c6 00 [2] fb }

  condition:
    any of them
}