rule TTP_XOR_MULT_DOSStub_a878 {
  strings:
    $key_a878 = { fc 10 [2] 88 08 [2] cf 0a [2] 88 1b [2] c6 17 [2] ca 1d [2] dd 16 [2] c6 58 [2] fb }

  condition:
    any of them
}