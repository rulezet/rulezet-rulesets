rule TTP_XOR_MULT_DOSStub_a864 {
  strings:
    $key_a864 = { fc 0c [2] 88 14 [2] cf 16 [2] 88 07 [2] c6 0b [2] ca 01 [2] dd 0a [2] c6 44 [2] fb }

  condition:
    any of them
}