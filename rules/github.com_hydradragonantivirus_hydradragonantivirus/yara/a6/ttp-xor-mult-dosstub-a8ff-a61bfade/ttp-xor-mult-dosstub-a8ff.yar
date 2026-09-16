rule TTP_XOR_MULT_DOSStub_a8ff {
  strings:
    $key_a8ff = { fc 97 [2] 88 8f [2] cf 8d [2] 88 9c [2] c6 90 [2] ca 9a [2] dd 91 [2] c6 df [2] fb }

  condition:
    any of them
}