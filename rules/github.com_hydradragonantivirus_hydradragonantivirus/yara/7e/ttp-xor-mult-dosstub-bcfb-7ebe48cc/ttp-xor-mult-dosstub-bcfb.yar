rule TTP_XOR_MULT_DOSStub_bcfb {
  strings:
    $key_bcfb = { e8 93 [2] 9c 8b [2] db 89 [2] 9c 98 [2] d2 94 [2] de 9e [2] c9 95 [2] d2 db [2] ef }

  condition:
    any of them
}