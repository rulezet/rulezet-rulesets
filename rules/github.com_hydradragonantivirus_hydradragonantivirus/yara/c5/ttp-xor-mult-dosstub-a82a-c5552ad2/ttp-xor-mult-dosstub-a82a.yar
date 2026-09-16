rule TTP_XOR_MULT_DOSStub_a82a {
  strings:
    $key_a82a = { fc 42 [2] 88 5a [2] cf 58 [2] 88 49 [2] c6 45 [2] ca 4f [2] dd 44 [2] c6 0a [2] fb }

  condition:
    any of them
}