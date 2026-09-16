rule TTP_XOR_MULT_DOSStub_a834 {
  strings:
    $key_a834 = { fc 5c [2] 88 44 [2] cf 46 [2] 88 57 [2] c6 5b [2] ca 51 [2] dd 5a [2] c6 14 [2] fb }

  condition:
    any of them
}