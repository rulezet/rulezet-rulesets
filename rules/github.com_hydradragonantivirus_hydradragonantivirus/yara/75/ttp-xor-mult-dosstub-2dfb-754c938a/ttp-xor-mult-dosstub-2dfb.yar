rule TTP_XOR_MULT_DOSStub_2dfb {
  strings:
    $key_2dfb = { 79 93 [2] 0d 8b [2] 4a 89 [2] 0d 98 [2] 43 94 [2] 4f 9e [2] 58 95 [2] 43 db [2] 7e }

  condition:
    any of them
}