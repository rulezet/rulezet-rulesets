rule TTP_XOR_MULT_DOSStub_a851 {
  strings:
    $key_a851 = { fc 39 [2] 88 21 [2] cf 23 [2] 88 32 [2] c6 3e [2] ca 34 [2] dd 3f [2] c6 71 [2] fb }

  condition:
    any of them
}