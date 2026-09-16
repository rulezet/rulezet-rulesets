rule TTP_XOR_MULT_DOSStub_a85d {
  strings:
    $key_a85d = { fc 35 [2] 88 2d [2] cf 2f [2] 88 3e [2] c6 32 [2] ca 38 [2] dd 33 [2] c6 7d [2] fb }

  condition:
    any of them
}