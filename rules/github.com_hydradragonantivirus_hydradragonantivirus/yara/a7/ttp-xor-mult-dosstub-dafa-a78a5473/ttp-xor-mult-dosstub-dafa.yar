rule TTP_XOR_MULT_DOSStub_dafa {
  strings:
    $key_dafa = { 8e 92 [2] fa 8a [2] bd 88 [2] fa 99 [2] b4 95 [2] b8 9f [2] af 94 [2] b4 da [2] 89 }

  condition:
    any of them
}