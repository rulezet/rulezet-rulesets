rule TTP_XOR_MULT_DOSStub_a81d {
  strings:
    $key_a81d = { fc 75 [2] 88 6d [2] cf 6f [2] 88 7e [2] c6 72 [2] ca 78 [2] dd 73 [2] c6 3d [2] fb }

  condition:
    any of them
}