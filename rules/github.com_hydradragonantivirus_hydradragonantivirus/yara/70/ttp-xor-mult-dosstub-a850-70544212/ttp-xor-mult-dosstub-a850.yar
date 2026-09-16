rule TTP_XOR_MULT_DOSStub_a850 {
  strings:
    $key_a850 = { fc 38 [2] 88 20 [2] cf 22 [2] 88 33 [2] c6 3f [2] ca 35 [2] dd 3e [2] c6 70 [2] fb }

  condition:
    any of them
}