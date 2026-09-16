rule TTP_XOR_MULT_DOSStub_a84f {
  strings:
    $key_a84f = { fc 27 [2] 88 3f [2] cf 3d [2] 88 2c [2] c6 20 [2] ca 2a [2] dd 21 [2] c6 6f [2] fb }

  condition:
    any of them
}