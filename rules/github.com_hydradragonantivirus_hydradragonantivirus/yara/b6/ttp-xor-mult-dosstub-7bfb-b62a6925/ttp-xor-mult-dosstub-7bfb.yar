rule TTP_XOR_MULT_DOSStub_7bfb {
  strings:
    $key_7bfb = { 2f 93 [2] 5b 8b [2] 1c 89 [2] 5b 98 [2] 15 94 [2] 19 9e [2] 0e 95 [2] 15 db [2] 28 }

  condition:
    any of them
}