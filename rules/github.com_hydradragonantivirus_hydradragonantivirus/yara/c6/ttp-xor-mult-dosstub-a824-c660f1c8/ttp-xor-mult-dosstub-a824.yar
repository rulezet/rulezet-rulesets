rule TTP_XOR_MULT_DOSStub_a824 {
  strings:
    $key_a824 = { fc 4c [2] 88 54 [2] cf 56 [2] 88 47 [2] c6 4b [2] ca 41 [2] dd 4a [2] c6 04 [2] fb }

  condition:
    any of them
}