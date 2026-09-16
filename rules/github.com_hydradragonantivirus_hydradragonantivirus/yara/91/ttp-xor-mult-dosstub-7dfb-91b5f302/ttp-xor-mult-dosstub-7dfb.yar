rule TTP_XOR_MULT_DOSStub_7dfb {
  strings:
    $key_7dfb = { 29 93 [2] 5d 8b [2] 1a 89 [2] 5d 98 [2] 13 94 [2] 1f 9e [2] 08 95 [2] 13 db [2] 2e }

  condition:
    any of them
}