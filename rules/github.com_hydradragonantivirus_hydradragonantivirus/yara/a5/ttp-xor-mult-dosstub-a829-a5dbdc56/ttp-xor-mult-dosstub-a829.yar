rule TTP_XOR_MULT_DOSStub_a829 {
  strings:
    $key_a829 = { fc 41 [2] 88 59 [2] cf 5b [2] 88 4a [2] c6 46 [2] ca 4c [2] dd 47 [2] c6 09 [2] fb }

  condition:
    any of them
}