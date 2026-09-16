rule TTP_XOR_MULT_DOSStub_3ffb {
  strings:
    $key_3ffb = { 6b 93 [2] 1f 8b [2] 58 89 [2] 1f 98 [2] 51 94 [2] 5d 9e [2] 4a 95 [2] 51 db [2] 6c }

  condition:
    any of them
}