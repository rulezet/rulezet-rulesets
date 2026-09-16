rule TTP_XOR_MULT_DOSStub_a8f7 {
  strings:
    $key_a8f7 = { fc 9f [2] 88 87 [2] cf 85 [2] 88 94 [2] c6 98 [2] ca 92 [2] dd 99 [2] c6 d7 [2] fb }

  condition:
    any of them
}