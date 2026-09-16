rule TTP_XOR_MULT_DOSStub_a8e0 {
  strings:
    $key_a8e0 = { fc 88 [2] 88 90 [2] cf 92 [2] 88 83 [2] c6 8f [2] ca 85 [2] dd 8e [2] c6 c0 [2] fb }

  condition:
    any of them
}