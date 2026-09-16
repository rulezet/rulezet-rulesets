rule TTP_XOR_MULT_DOSStub_a856 {
  strings:
    $key_a856 = { fc 3e [2] 88 26 [2] cf 24 [2] 88 35 [2] c6 39 [2] ca 33 [2] dd 38 [2] c6 76 [2] fb }

  condition:
    any of them
}