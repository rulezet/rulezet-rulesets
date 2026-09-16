rule TTP_XOR_MULT_DOSStub_a81f {
  strings:
    $key_a81f = { fc 77 [2] 88 6f [2] cf 6d [2] 88 7c [2] c6 70 [2] ca 7a [2] dd 71 [2] c6 3f [2] fb }

  condition:
    any of them
}