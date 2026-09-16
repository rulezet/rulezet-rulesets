rule TTP_XOR_MULT_DOSStub_a826 {
  strings:
    $key_a826 = { fc 4e [2] 88 56 [2] cf 54 [2] 88 45 [2] c6 49 [2] ca 43 [2] dd 48 [2] c6 06 [2] fb }

  condition:
    any of them
}