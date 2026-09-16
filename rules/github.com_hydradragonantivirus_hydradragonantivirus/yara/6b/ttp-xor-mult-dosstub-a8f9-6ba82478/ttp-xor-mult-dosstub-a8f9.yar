rule TTP_XOR_MULT_DOSStub_a8f9 {
  strings:
    $key_a8f9 = { fc 91 [2] 88 89 [2] cf 8b [2] 88 9a [2] c6 96 [2] ca 9c [2] dd 97 [2] c6 d9 [2] fb }

  condition:
    any of them
}