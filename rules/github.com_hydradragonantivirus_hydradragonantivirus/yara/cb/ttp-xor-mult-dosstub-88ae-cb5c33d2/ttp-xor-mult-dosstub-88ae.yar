rule TTP_XOR_MULT_DOSStub_88ae {
  strings:
    $key_88ae = { dc c6 [2] a8 de [2] ef dc [2] a8 cd [2] e6 c1 [2] ea cb [2] fd c0 [2] e6 8e [2] db }

  condition:
    any of them
}