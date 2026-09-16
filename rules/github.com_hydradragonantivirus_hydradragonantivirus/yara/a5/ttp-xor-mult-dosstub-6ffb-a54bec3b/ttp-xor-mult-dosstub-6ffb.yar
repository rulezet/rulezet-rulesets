rule TTP_XOR_MULT_DOSStub_6ffb {
  strings:
    $key_6ffb = { 3b 93 [2] 4f 8b [2] 08 89 [2] 4f 98 [2] 01 94 [2] 0d 9e [2] 1a 95 [2] 01 db [2] 3c }

  condition:
    any of them
}