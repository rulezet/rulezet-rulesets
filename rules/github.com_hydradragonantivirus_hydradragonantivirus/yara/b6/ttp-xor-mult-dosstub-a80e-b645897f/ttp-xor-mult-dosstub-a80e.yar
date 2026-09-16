rule TTP_XOR_MULT_DOSStub_a80e {
  strings:
    $key_a80e = { fc 66 [2] 88 7e [2] cf 7c [2] 88 6d [2] c6 61 [2] ca 6b [2] dd 60 [2] c6 2e [2] fb }

  condition:
    any of them
}