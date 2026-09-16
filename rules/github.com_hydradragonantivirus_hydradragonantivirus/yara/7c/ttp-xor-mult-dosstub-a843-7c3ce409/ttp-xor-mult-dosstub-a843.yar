rule TTP_XOR_MULT_DOSStub_a843 {
  strings:
    $key_a843 = { fc 2b [2] 88 33 [2] cf 31 [2] 88 20 [2] c6 2c [2] ca 26 [2] dd 2d [2] c6 63 [2] fb }

  condition:
    any of them
}