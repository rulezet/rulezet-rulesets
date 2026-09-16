rule TTP_XOR_MULT_DOSStub_a862 {
  strings:
    $key_a862 = { fc 0a [2] 88 12 [2] cf 10 [2] 88 01 [2] c6 0d [2] ca 07 [2] dd 0c [2] c6 42 [2] fb }

  condition:
    any of them
}