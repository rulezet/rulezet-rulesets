rule TTP_XOR_MULT_DOSStub_a8e5 {
  strings:
    $key_a8e5 = { fc 8d [2] 88 95 [2] cf 97 [2] 88 86 [2] c6 8a [2] ca 80 [2] dd 8b [2] c6 c5 [2] fb }

  condition:
    any of them
}