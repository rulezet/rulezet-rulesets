rule TTP_XOR_MULT_DOSStub_c8ae {
  strings:
    $key_c8ae = { 9c c6 [2] e8 de [2] af dc [2] e8 cd [2] a6 c1 [2] aa cb [2] bd c0 [2] a6 8e [2] 9b }

  condition:
    any of them
}