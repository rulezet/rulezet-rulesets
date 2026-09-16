rule TTP_XOR_MULT_DOSStub_a80a {
  strings:
    $key_a80a = { fc 62 [2] 88 7a [2] cf 78 [2] 88 69 [2] c6 65 [2] ca 6f [2] dd 64 [2] c6 2a [2] fb }

  condition:
    any of them
}