rule TTP_XOR_MULT_DOSStub_a849 {
  strings:
    $key_a849 = { fc 21 [2] 88 39 [2] cf 3b [2] 88 2a [2] c6 26 [2] ca 2c [2] dd 27 [2] c6 69 [2] fb }

  condition:
    any of them
}