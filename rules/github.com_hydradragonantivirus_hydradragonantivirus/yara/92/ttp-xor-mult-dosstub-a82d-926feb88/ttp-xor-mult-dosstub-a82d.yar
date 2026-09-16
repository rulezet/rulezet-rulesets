rule TTP_XOR_MULT_DOSStub_a82d {
  strings:
    $key_a82d = { fc 45 [2] 88 5d [2] cf 5f [2] 88 4e [2] c6 42 [2] ca 48 [2] dd 43 [2] c6 0d [2] fb }

  condition:
    any of them
}