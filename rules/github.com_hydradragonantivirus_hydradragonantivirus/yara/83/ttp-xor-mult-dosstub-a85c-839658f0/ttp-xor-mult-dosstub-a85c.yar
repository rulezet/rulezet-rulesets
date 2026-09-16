rule TTP_XOR_MULT_DOSStub_a85c {
  strings:
    $key_a85c = { fc 34 [2] 88 2c [2] cf 2e [2] 88 3f [2] c6 33 [2] ca 39 [2] dd 32 [2] c6 7c [2] fb }

  condition:
    any of them
}