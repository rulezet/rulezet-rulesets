rule TTP_XOR_MULT_DOSStub_a81c {
  strings:
    $key_a81c = { fc 74 [2] 88 6c [2] cf 6e [2] 88 7f [2] c6 73 [2] ca 79 [2] dd 72 [2] c6 3c [2] fb }

  condition:
    any of them
}