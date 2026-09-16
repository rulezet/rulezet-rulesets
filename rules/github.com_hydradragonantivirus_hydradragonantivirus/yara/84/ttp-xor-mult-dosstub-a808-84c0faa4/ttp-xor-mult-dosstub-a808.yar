rule TTP_XOR_MULT_DOSStub_a808 {
  strings:
    $key_a808 = { fc 60 [2] 88 78 [2] cf 7a [2] 88 6b [2] c6 67 [2] ca 6d [2] dd 66 [2] c6 28 [2] fb }

  condition:
    any of them
}