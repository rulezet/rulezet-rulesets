rule TTP_XOR_MULT_DOSStub_a835 {
  strings:
    $key_a835 = { fc 5d [2] 88 45 [2] cf 47 [2] 88 56 [2] c6 5a [2] ca 50 [2] dd 5b [2] c6 15 [2] fb }

  condition:
    any of them
}