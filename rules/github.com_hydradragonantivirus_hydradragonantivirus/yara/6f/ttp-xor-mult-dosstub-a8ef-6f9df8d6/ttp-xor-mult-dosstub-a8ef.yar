rule TTP_XOR_MULT_DOSStub_a8ef {
  strings:
    $key_a8ef = { fc 87 [2] 88 9f [2] cf 9d [2] 88 8c [2] c6 80 [2] ca 8a [2] dd 81 [2] c6 cf [2] fb }

  condition:
    any of them
}