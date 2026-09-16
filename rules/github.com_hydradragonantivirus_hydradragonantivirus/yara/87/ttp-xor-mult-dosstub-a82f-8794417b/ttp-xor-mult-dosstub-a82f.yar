rule TTP_XOR_MULT_DOSStub_a82f {
  strings:
    $key_a82f = { fc 47 [2] 88 5f [2] cf 5d [2] 88 4c [2] c6 40 [2] ca 4a [2] dd 41 [2] c6 0f [2] fb }

  condition:
    any of them
}