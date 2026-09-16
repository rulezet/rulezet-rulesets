rule TTP_XOR_MULT_DOSStub_3dfb {
  strings:
    $key_3dfb = { 69 93 [2] 1d 8b [2] 5a 89 [2] 1d 98 [2] 53 94 [2] 5f 9e [2] 48 95 [2] 53 db [2] 6e }

  condition:
    any of them
}