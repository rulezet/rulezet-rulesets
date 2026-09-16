rule TTP_XOR_MULT_DOSStub_a857 {
  strings:
    $key_a857 = { fc 3f [2] 88 27 [2] cf 25 [2] 88 34 [2] c6 38 [2] ca 32 [2] dd 39 [2] c6 77 [2] fb }

  condition:
    any of them
}