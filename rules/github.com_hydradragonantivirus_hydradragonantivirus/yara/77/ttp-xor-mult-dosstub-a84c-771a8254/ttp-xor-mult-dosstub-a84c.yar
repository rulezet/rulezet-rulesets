rule TTP_XOR_MULT_DOSStub_a84c {
  strings:
    $key_a84c = { fc 24 [2] 88 3c [2] cf 3e [2] 88 2f [2] c6 23 [2] ca 29 [2] dd 22 [2] c6 6c [2] fb }

  condition:
    any of them
}