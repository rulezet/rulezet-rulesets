rule TTP_XOR_MULT_DOSStub_a837 {
  strings:
    $key_a837 = { fc 5f [2] 88 47 [2] cf 45 [2] 88 54 [2] c6 58 [2] ca 52 [2] dd 59 [2] c6 17 [2] fb }

  condition:
    any of them
}