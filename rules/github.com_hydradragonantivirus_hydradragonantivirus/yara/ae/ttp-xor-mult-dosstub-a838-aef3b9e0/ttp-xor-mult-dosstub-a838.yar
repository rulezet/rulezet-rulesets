rule TTP_XOR_MULT_DOSStub_a838 {
  strings:
    $key_a838 = { fc 50 [2] 88 48 [2] cf 4a [2] 88 5b [2] c6 57 [2] ca 5d [2] dd 56 [2] c6 18 [2] fb }

  condition:
    any of them
}