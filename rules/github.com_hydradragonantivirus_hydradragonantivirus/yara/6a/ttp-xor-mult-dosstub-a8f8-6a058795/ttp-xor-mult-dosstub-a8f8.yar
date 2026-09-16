rule TTP_XOR_MULT_DOSStub_a8f8 {
  strings:
    $key_a8f8 = { fc 90 [2] 88 88 [2] cf 8a [2] 88 9b [2] c6 97 [2] ca 9d [2] dd 96 [2] c6 d8 [2] fb }

  condition:
    any of them
}