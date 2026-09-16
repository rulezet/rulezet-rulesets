rule TTP_XOR_MULT_DOSStub_a84d {
  strings:
    $key_a84d = { fc 25 [2] 88 3d [2] cf 3f [2] 88 2e [2] c6 22 [2] ca 28 [2] dd 23 [2] c6 6d [2] fb }

  condition:
    any of them
}