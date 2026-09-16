rule TTP_XOR_MULT_DOSStub_a82e {
  strings:
    $key_a82e = { fc 46 [2] 88 5e [2] cf 5c [2] 88 4d [2] c6 41 [2] ca 4b [2] dd 40 [2] c6 0e [2] fb }

  condition:
    any of them
}