rule TTP_XOR_MULT_DOSStub_a874 {
  strings:
    $key_a874 = { fc 1c [2] 88 04 [2] cf 06 [2] 88 17 [2] c6 1b [2] ca 11 [2] dd 1a [2] c6 54 [2] fb }

  condition:
    any of them
}