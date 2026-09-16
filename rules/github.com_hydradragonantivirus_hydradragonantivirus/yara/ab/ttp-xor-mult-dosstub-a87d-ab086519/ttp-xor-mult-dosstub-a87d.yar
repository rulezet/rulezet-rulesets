rule TTP_XOR_MULT_DOSStub_a87d {
  strings:
    $key_a87d = { fc 15 [2] 88 0d [2] cf 0f [2] 88 1e [2] c6 12 [2] ca 18 [2] dd 13 [2] c6 5d [2] fb }

  condition:
    any of them
}