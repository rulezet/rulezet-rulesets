rule TTP_XOR_MULT_DOSStub_a859 {
  strings:
    $key_a859 = { fc 31 [2] 88 29 [2] cf 2b [2] 88 3a [2] c6 36 [2] ca 3c [2] dd 37 [2] c6 79 [2] fb }

  condition:
    any of them
}