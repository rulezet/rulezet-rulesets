rule TTP_XOR_MULT_DOSStub_a817 {
  strings:
    $key_a817 = { fc 7f [2] 88 67 [2] cf 65 [2] 88 74 [2] c6 78 [2] ca 72 [2] dd 79 [2] c6 37 [2] fb }

  condition:
    any of them
}