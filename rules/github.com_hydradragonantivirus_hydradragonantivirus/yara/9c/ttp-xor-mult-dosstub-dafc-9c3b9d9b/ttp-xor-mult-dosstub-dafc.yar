rule TTP_XOR_MULT_DOSStub_dafc {
  strings:
    $key_dafc = { 8e 94 [2] fa 8c [2] bd 8e [2] fa 9f [2] b4 93 [2] b8 99 [2] af 92 [2] b4 dc [2] 89 }

  condition:
    any of them
}