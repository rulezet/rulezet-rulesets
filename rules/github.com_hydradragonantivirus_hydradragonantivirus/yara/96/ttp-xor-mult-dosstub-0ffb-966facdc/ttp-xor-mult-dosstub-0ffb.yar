rule TTP_XOR_MULT_DOSStub_0ffb {
  strings:
    $key_0ffb = { 5b 93 [2] 2f 8b [2] 68 89 [2] 2f 98 [2] 61 94 [2] 6d 9e [2] 7a 95 [2] 61 db [2] 5c }

  condition:
    any of them
}