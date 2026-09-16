rule TTP_XOR_MULT_DOSStub_a85e {
  strings:
    $key_a85e = { fc 36 [2] 88 2e [2] cf 2c [2] 88 3d [2] c6 31 [2] ca 3b [2] dd 30 [2] c6 7e [2] fb }

  condition:
    any of them
}