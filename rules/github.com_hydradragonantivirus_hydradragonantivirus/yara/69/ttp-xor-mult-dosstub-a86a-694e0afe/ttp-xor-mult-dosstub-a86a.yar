rule TTP_XOR_MULT_DOSStub_a86a {
  strings:
    $key_a86a = { fc 02 [2] 88 1a [2] cf 18 [2] 88 09 [2] c6 05 [2] ca 0f [2] dd 04 [2] c6 4a [2] fb }

  condition:
    any of them
}