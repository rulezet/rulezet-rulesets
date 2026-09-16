rule TTP_XOR_MULT_DOSStub_a84e {
  strings:
    $key_a84e = { fc 26 [2] 88 3e [2] cf 3c [2] 88 2d [2] c6 21 [2] ca 2b [2] dd 20 [2] c6 6e [2] fb }

  condition:
    any of them
}